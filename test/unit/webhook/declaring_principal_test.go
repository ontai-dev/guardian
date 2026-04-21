package webhook_test

import (
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/ontai-dev/guardian/internal/webhook"
)

func TestDeclaringPrincipal_CreateStampsAnnotation(t *testing.T) {
	srv, window := newDeclaringPrincipalServer(false)

	obj := mustMarshal(map[string]interface{}{
		"apiVersion": "platform.ontai.dev/v1alpha1",
		"kind":       "TalosCluster",
		"metadata":   map[string]interface{}{"name": "prod"},
	})

	resp := srv.Handle(t.Context(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Kind:      metav1.GroupVersionKind{Kind: "TalosCluster"},
			UserInfo:  authenticationv1.UserInfo{Username: "alice@example.com"},
			Object:    runtime.RawExtension{Raw: obj},
		},
	})

	if !resp.Allowed {
		t.Fatalf("expected Allowed, got denied: %s", resp.Result.Message)
	}
	if resp.PatchType == nil {
		t.Fatal("expected patch in response but PatchType is nil")
	}

	var ops []map[string]interface{}
	if err := json.Unmarshal(resp.Patch, &ops); err != nil {
		t.Fatalf("parse patch: %v", err)
	}
	found := false
	for _, op := range ops {
		path, _ := op["path"].(string)
		val, _ := op["value"].(string)
		if val == "alice@example.com" && (path == "/metadata/annotations/infrastructure.ontai.dev~1declaring-principal" ||
			path == "/metadata/annotations") {
			found = true
		}
		// Handle the case where annotations object is added wholesale.
		if m, ok := op["value"].(map[string]interface{}); ok {
			if m[webhook.AnnotationDeclaringPrincipal] == "alice@example.com" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("declaring-principal annotation not found in patch: %s", resp.Patch)
	}
	_ = window
}

func TestDeclaringPrincipal_UpdateDoesNotStamp(t *testing.T) {
	srv, _ := newDeclaringPrincipalServer(false)

	obj := mustMarshal(map[string]interface{}{
		"apiVersion": "platform.ontai.dev/v1alpha1",
		"kind":       "TalosCluster",
		"metadata":   map[string]interface{}{"name": "prod"},
	})

	resp := srv.Handle(t.Context(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Update,
			Kind:      metav1.GroupVersionKind{Kind: "TalosCluster"},
			UserInfo:  authenticationv1.UserInfo{Username: "alice@example.com"},
			Object:    runtime.RawExtension{Raw: obj},
		},
	})

	if !resp.Allowed {
		t.Fatalf("expected Allowed, got denied")
	}
	if resp.PatchType != nil {
		t.Error("UPDATE must not produce a patch")
	}
}

func TestDeclaringPrincipal_BootstrapWindowOpen_NoStamp(t *testing.T) {
	srv, _ := newDeclaringPrincipalServer(true)

	obj := mustMarshal(map[string]interface{}{
		"apiVersion": "platform.ontai.dev/v1alpha1",
		"kind":       "TalosCluster",
		"metadata":   map[string]interface{}{"name": "prod"},
	})

	resp := srv.Handle(t.Context(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Kind:      metav1.GroupVersionKind{Kind: "TalosCluster"},
			UserInfo:  authenticationv1.UserInfo{Username: "alice@example.com"},
			Object:    runtime.RawExtension{Raw: obj},
		},
	})

	if !resp.Allowed {
		t.Fatalf("expected Allowed, got denied")
	}
	if resp.PatchType != nil {
		t.Error("bootstrap window open: must not stamp annotation")
	}
}

func TestDeclaringPrincipal_ServiceAccountRecordedAsIs(t *testing.T) {
	srv, _ := newDeclaringPrincipalServer(false)

	obj := mustMarshal(map[string]interface{}{
		"apiVersion": "security.ontai.dev/v1alpha1",
		"kind":       "RBACPolicy",
		"metadata":   map[string]interface{}{"name": "default-policy"},
	})
	sa := "system:serviceaccount:seam-system:platform-controller"

	resp := srv.Handle(t.Context(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Kind:      metav1.GroupVersionKind{Kind: "RBACPolicy"},
			UserInfo:  authenticationv1.UserInfo{Username: sa},
			Object:    runtime.RawExtension{Raw: obj},
		},
	})

	if !resp.Allowed {
		t.Fatalf("expected Allowed")
	}
	if resp.PatchType == nil {
		t.Fatal("expected patch")
	}
	found := false
	var ops []map[string]interface{}
	_ = json.Unmarshal(resp.Patch, &ops)
	for _, op := range ops {
		if v, ok := op["value"].(string); ok && v == sa {
			found = true
		}
		if m, ok := op["value"].(map[string]interface{}); ok {
			if m[webhook.AnnotationDeclaringPrincipal] == sa {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("service account principal not recorded: %s", resp.Patch)
	}
}

func TestDeclaringPrincipal_HumanEmailRecordedAsIs(t *testing.T) {
	srv, _ := newDeclaringPrincipalServer(false)

	obj := mustMarshal(map[string]interface{}{
		"apiVersion": "infra.ontai.dev/v1alpha1",
		"kind":       "PackExecution",
		"metadata":   map[string]interface{}{"name": "exec-001"},
	})
	email := "bob@company.org"

	resp := srv.Handle(t.Context(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Kind:      metav1.GroupVersionKind{Kind: "PackExecution"},
			UserInfo:  authenticationv1.UserInfo{Username: email},
			Object:    runtime.RawExtension{Raw: obj},
		},
	})

	if !resp.Allowed {
		t.Fatalf("expected Allowed")
	}
	if resp.PatchType == nil {
		t.Fatal("expected patch")
	}
	found := false
	var ops []map[string]interface{}
	_ = json.Unmarshal(resp.Patch, &ops)
	for _, op := range ops {
		if v, ok := op["value"].(string); ok && v == email {
			found = true
		}
		if m, ok := op["value"].(map[string]interface{}); ok {
			if m[webhook.AnnotationDeclaringPrincipal] == email {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("email principal not recorded: %s", resp.Patch)
	}
}

// newDeclaringPrincipalServer returns a DeclaringPrincipalHandler and its
// BootstrapWindow. bootstrapOpen controls whether the window is open (pre-close).
func newDeclaringPrincipalServer(bootstrapOpen bool) (*webhook.DeclaringPrincipalHandler, *webhook.BootstrapWindow) {
	w := webhook.NewBootstrapWindow()
	if !bootstrapOpen {
		w.Close()
	}
	return webhook.NewDeclaringPrincipalHandler(w), w
}

func mustMarshal(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
