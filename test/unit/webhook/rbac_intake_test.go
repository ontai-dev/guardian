// Package webhook_test contains unit tests for the RBAC intake handler.
//
// Tests verify that POST /rbac-intake:
//  1. Wraps submitted RBAC resources with the guardian ownership annotation.
//  2. Applies resources to the cluster (creates them if absent).
//  3. Returns 200 OK with the correct wrapped count.
//  4. Returns 400 on invalid JSON.
//  5. Returns 200 with wrapped=0 for an empty resources list.
//
// guardian-schema.md §6, CS-INV-007.
package webhook_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/ontai-dev/guardian/internal/webhook"
)

func intakeScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	return s
}

// clusterRoleJSON returns a minimal ClusterRole as json.RawMessage.
func clusterRoleJSON(t *testing.T, name string) json.RawMessage {
	t.Helper()
	cr := &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	b, err := json.Marshal(cr)
	if err != nil {
		t.Fatalf("marshal ClusterRole: %v", err)
	}
	return b
}

// postIntake sends a POST /rbac-intake request to the handler and returns the recorder.
func postIntake(t *testing.T, h http.Handler, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, webhook.RBACIntakeWebhookPath, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	return rw
}

// TestRBACIntake_WrapsResourceWithOwnerAnnotation verifies that a submitted ClusterRole
// is applied to the cluster with ontai.dev/rbac-owner=guardian stamped on it.
func TestRBACIntake_WrapsResourceWithOwnerAnnotation(t *testing.T) {
	s := intakeScheme(t)
	c := fake.NewClientBuilder().WithScheme(s).Build()
	h := webhook.NewRBACIntakeHandler(c, nil)

	req := webhook.IntakeRequest{
		Component: "cilium",
		Resources: []json.RawMessage{clusterRoleJSON(t, "rbac-cilium")},
	}
	rw := postIntake(t, h, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(rbacv1.SchemeGroupVersion.WithKind("ClusterRole"))
	if err := c.Get(context.Background(), types.NamespacedName{Name: "rbac-cilium"}, obj); err != nil {
		t.Fatalf("get applied ClusterRole: %v", err)
	}
	if got := obj.GetAnnotations()["ontai.dev/rbac-owner"]; got != "guardian" {
		t.Errorf("ontai.dev/rbac-owner: got %q want %q", got, "guardian")
	}
}

// TestRBACIntake_WrappedCountMatchesResources verifies that the response body
// reports the exact number of submitted resources as wrapped.
func TestRBACIntake_WrappedCountMatchesResources(t *testing.T) {
	s := intakeScheme(t)
	c := fake.NewClientBuilder().WithScheme(s).Build()
	h := webhook.NewRBACIntakeHandler(c, nil)

	req := webhook.IntakeRequest{
		Component: "kueue",
		Resources: []json.RawMessage{
			clusterRoleJSON(t, "rbac-kueue-1"),
			clusterRoleJSON(t, "rbac-kueue-2"),
			clusterRoleJSON(t, "rbac-kueue-3"),
		},
	}
	rw := postIntake(t, h, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}

	var resp webhook.IntakeResponse
	if err := json.NewDecoder(rw.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Wrapped != 3 {
		t.Errorf("wrapped: got %d want 3", resp.Wrapped)
	}
	if resp.Component != "kueue" {
		t.Errorf("component: got %q want %q", resp.Component, "kueue")
	}
}

// TestRBACIntake_EmptyResourcesReturns200 verifies that an intake request with an
// empty resources list returns 200 OK with wrapped=0.
func TestRBACIntake_EmptyResourcesReturns200(t *testing.T) {
	s := intakeScheme(t)
	c := fake.NewClientBuilder().WithScheme(s).Build()
	h := webhook.NewRBACIntakeHandler(c, nil)

	req := webhook.IntakeRequest{Component: "cnpg", Resources: nil}
	rw := postIntake(t, h, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}

	var resp webhook.IntakeResponse
	if err := json.NewDecoder(rw.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Wrapped != 0 {
		t.Errorf("wrapped: got %d want 0", resp.Wrapped)
	}
}

// TestRBACIntake_InvalidJSONReturns400 verifies that a malformed request body
// causes the handler to return 400 Bad Request.
func TestRBACIntake_InvalidJSONReturns400(t *testing.T) {
	s := intakeScheme(t)
	c := fake.NewClientBuilder().WithScheme(s).Build()
	h := webhook.NewRBACIntakeHandler(c, nil)

	req := httptest.NewRequest(http.MethodPost, webhook.RBACIntakeWebhookPath,
		bytes.NewBufferString("not-json"))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rw.Code, rw.Body.String())
	}
}

// TestRBACIntake_NonPOSTMethodNotAllowed verifies that a GET request to the intake
// endpoint returns 405 Method Not Allowed.
func TestRBACIntake_NonPOSTMethodNotAllowed(t *testing.T) {
	s := intakeScheme(t)
	c := fake.NewClientBuilder().WithScheme(s).Build()
	h := webhook.NewRBACIntakeHandler(c, nil)

	req := httptest.NewRequest(http.MethodGet, webhook.RBACIntakeWebhookPath, nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rw.Code)
	}
}
