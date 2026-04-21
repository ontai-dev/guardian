// Package webhook_test -- unit tests for the /rbac-intake/pack handler.
//
// Tests verify that POST /rbac-intake/pack:
//  1. Wraps submitted YAML manifests with the guardian ownership annotation.
//  2. Returns 200 OK with correct componentName, targetCluster, and wrapped count.
//  3. Returns 400 when componentName or targetCluster is absent.
//  4. Returns 400 on invalid YAML.
//  5. Returns 200 with wrapped=0 for an empty manifests list.
//  6. Returns 405 for non-POST methods.
//
// guardian-schema.md §6, wrapper-schema.md §4, INV-004.
package webhook_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/ontai-dev/guardian/internal/webhook"
)

// clusterRoleYAML returns a minimal ClusterRole YAML string for use in pack intake tests.
func clusterRoleYAML(name string) string {
	return "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: " + name
}

// serviceAccountYAML returns a minimal ServiceAccount YAML string.
func serviceAccountYAML(name, namespace string) string {
	return "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: " + name + "\n  namespace: " + namespace
}

// postPackIntake sends a POST /rbac-intake/pack request and returns the recorder.
func postPackIntake(t *testing.T, h http.Handler, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, webhook.RBACPackIntakeWebhookPath, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	return rw
}

// TestPackIntake_WrapsManifestWithOwnerAnnotation verifies that a YAML ClusterRole
// manifest is applied to the cluster with ontai.dev/rbac-owner=guardian stamped.
func TestPackIntake_WrapsManifestWithOwnerAnnotation(t *testing.T) {
	s := intakeScheme(t)
	c := newFakeClientWithRBAC(t, s)
	h := webhook.NewRBACPackIntakeHandler(c, nil)

	req := webhook.PackIntakeRequest{
		ComponentName: "nginx-ingress",
		Manifests:     []string{clusterRoleYAML("ingress-nginx")},
		TargetCluster: "ccs-mgmt",
	}
	rw := postPackIntake(t, h, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(rbacv1.SchemeGroupVersion.WithKind("ClusterRole"))
	if err := c.Get(context.Background(), types.NamespacedName{Name: "ingress-nginx"}, obj); err != nil {
		t.Fatalf("get applied ClusterRole: %v", err)
	}
	if got := obj.GetAnnotations()["ontai.dev/rbac-owner"]; got != "guardian" {
		t.Errorf("ontai.dev/rbac-owner: got %q want %q", got, "guardian")
	}
}

// TestPackIntake_ResponseCarriesComponentNameAndTargetCluster verifies that the
// response body echoes componentName and targetCluster from the request.
func TestPackIntake_ResponseCarriesComponentNameAndTargetCluster(t *testing.T) {
	s := intakeScheme(t)
	c := newFakeClientWithRBAC(t, s)
	h := webhook.NewRBACPackIntakeHandler(c, nil)

	req := webhook.PackIntakeRequest{
		ComponentName: "nginx-ingress",
		Manifests: []string{
			clusterRoleYAML("ingress-nginx-cr"),
			serviceAccountYAML("ingress-nginx-sa", "ingress-nginx"),
		},
		TargetCluster: "ccs-mgmt",
	}
	rw := postPackIntake(t, h, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}

	var resp webhook.PackIntakeResponse
	if err := json.NewDecoder(rw.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ComponentName != "nginx-ingress" {
		t.Errorf("componentName: got %q want %q", resp.ComponentName, "nginx-ingress")
	}
	if resp.TargetCluster != "ccs-mgmt" {
		t.Errorf("targetCluster: got %q want %q", resp.TargetCluster, "ccs-mgmt")
	}
	if resp.Wrapped != 2 {
		t.Errorf("wrapped: got %d want 2", resp.Wrapped)
	}
}

// TestPackIntake_EmptyManifestsReturns200WithZeroWrapped verifies that an intake
// request with no manifests returns 200 OK with wrapped=0.
func TestPackIntake_EmptyManifestsReturns200WithZeroWrapped(t *testing.T) {
	s := intakeScheme(t)
	c := newFakeClientWithRBAC(t, s)
	h := webhook.NewRBACPackIntakeHandler(c, nil)

	req := webhook.PackIntakeRequest{
		ComponentName: "empty-pack",
		Manifests:     nil,
		TargetCluster: "ccs-mgmt",
	}
	rw := postPackIntake(t, h, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}

	var resp webhook.PackIntakeResponse
	if err := json.NewDecoder(rw.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Wrapped != 0 {
		t.Errorf("wrapped: got %d want 0", resp.Wrapped)
	}
}

// TestPackIntake_MissingComponentNameReturns400 verifies that a request without
// componentName is rejected with 400 Bad Request.
func TestPackIntake_MissingComponentNameReturns400(t *testing.T) {
	s := intakeScheme(t)
	c := newFakeClientWithRBAC(t, s)
	h := webhook.NewRBACPackIntakeHandler(c, nil)

	req := webhook.PackIntakeRequest{
		Manifests:     []string{clusterRoleYAML("cr")},
		TargetCluster: "ccs-mgmt",
	}
	rw := postPackIntake(t, h, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rw.Code, rw.Body.String())
	}
}

// TestPackIntake_MissingTargetClusterReturns400 verifies that a request without
// targetCluster is rejected with 400 Bad Request.
func TestPackIntake_MissingTargetClusterReturns400(t *testing.T) {
	s := intakeScheme(t)
	c := newFakeClientWithRBAC(t, s)
	h := webhook.NewRBACPackIntakeHandler(c, nil)

	req := webhook.PackIntakeRequest{
		ComponentName: "nginx-ingress",
		Manifests:     []string{clusterRoleYAML("cr")},
	}
	rw := postPackIntake(t, h, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rw.Code, rw.Body.String())
	}
}

// TestPackIntake_InvalidYAMLReturns400 verifies that a malformed YAML manifest
// causes the handler to return 400 Bad Request.
func TestPackIntake_InvalidYAMLReturns400(t *testing.T) {
	s := intakeScheme(t)
	c := newFakeClientWithRBAC(t, s)
	h := webhook.NewRBACPackIntakeHandler(c, nil)

	req := webhook.PackIntakeRequest{
		ComponentName: "nginx-ingress",
		Manifests:     []string{"{{invalid yaml{{"},
		TargetCluster: "ccs-mgmt",
	}
	rw := postPackIntake(t, h, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rw.Code, rw.Body.String())
	}
}

// TestPackIntake_NonPOSTMethodNotAllowed verifies that a GET request returns 405.
func TestPackIntake_NonPOSTMethodNotAllowed(t *testing.T) {
	s := intakeScheme(t)
	c := newFakeClientWithRBAC(t, s)
	h := webhook.NewRBACPackIntakeHandler(c, nil)

	req := httptest.NewRequest(http.MethodGet, webhook.RBACPackIntakeWebhookPath, nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rw.Code)
	}
}

// newFakeClientWithRBAC returns a fake controller-runtime client with the RBAC
// scheme registered, suitable for pack intake handler tests.
func newFakeClientWithRBAC(t *testing.T, s *runtime.Scheme) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(s).Build()
}
