// Package webhook contains white-box tests for RBACAdmissionHandler audit event
// emission. These tests construct RBACAdmissionHandler directly, which requires
// white-box access to the unexported fields.
//
// guardian-schema.md §16.
package webhook

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/ontai-dev/guardian/internal/database"
)

// captureWriter records every Write call for assertion in tests.
type captureWriter struct {
	mu     sync.Mutex
	events []database.AuditEvent
}

func (w *captureWriter) Write(_ context.Context, event database.AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, event)
	return nil
}

func (w *captureWriter) written() []database.AuditEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]database.AuditEvent, len(w.events))
	copy(out, w.events)
	return out
}

// makeRawRole builds a minimal raw JSON payload for a Role admission request.
func makeRawRole(t *testing.T, annotations map[string]string) runtime.RawExtension {
	t.Helper()
	type meta struct {
		Annotations map[string]string `json:"annotations,omitempty"`
	}
	type obj struct {
		Metadata meta `json:"metadata"`
	}
	b, err := json.Marshal(obj{Metadata: meta{Annotations: annotations}})
	if err != nil {
		t.Fatalf("marshal raw role: %v", err)
	}
	return runtime.RawExtension{Raw: b}
}

// TestRBACAdmissionHandler_AuditWriter_WouldDeny verifies that the handler calls
// AuditWriter.Write with action="rbac.would_deny" when the namespace is in
// Observe mode and the resource is missing the ownership annotation.
func TestRBACAdmissionHandler_AuditWriter_WouldDeny(t *testing.T) {
	aw := &captureWriter{}
	window := NewBootstrapWindow()
	window.Close() // bootstrap window closed — policy is active

	handler := &RBACAdmissionHandler{
		bootstrapWindow: window,
		namespaceMode:   fixedMode(NamespaceModeObserve),
		auditWriter:     aw,
	}

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Name:      "test-role",
			Namespace: "default",
			Kind:      metav1.GroupVersionKind{Kind: "Role"},
			Operation: admissionv1.Create,
			UserInfo:  authv1.UserInfo{Username: "alice"},
			Object:    makeRawRole(t, nil), // no ownership annotation
		},
	}

	resp := handler.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Errorf("expected Allowed=true in Observe mode; got Allowed=false")
	}

	events := aw.written()
	found := false
	for _, e := range events {
		if e.Action == "rbac.would_deny" && e.Resource == "test-role" && e.Decision == "audit" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected audit event action=rbac.would_deny resource=test-role decision=audit, got: %+v", events)
	}
}

// TestRBACAdmissionHandler_AuditWriter_HardDeny verifies that the handler calls
// AuditWriter.Write with action="rbac.denied" when the namespace is in Enforce
// mode and the resource is missing the ownership annotation.
func TestRBACAdmissionHandler_AuditWriter_HardDeny(t *testing.T) {
	aw := &captureWriter{}
	window := NewBootstrapWindow()
	window.Close()

	handler := &RBACAdmissionHandler{
		bootstrapWindow: window,
		namespaceMode:   fixedMode(NamespaceModeEnforce),
		auditWriter:     aw,
	}

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Name:      "bad-role",
			Namespace: "default",
			Kind:      metav1.GroupVersionKind{Kind: "Role"},
			Operation: admissionv1.Create,
			UserInfo:  authv1.UserInfo{Username: "bob"},
			Object:    makeRawRole(t, nil),
		},
	}

	resp := handler.Handle(context.Background(), req)
	if resp.Allowed {
		t.Errorf("expected Allowed=false in Enforce mode with no annotation; got Allowed=true")
	}

	events := aw.written()
	found := false
	for _, e := range events {
		if e.Action == "rbac.denied" && e.Resource == "bad-role" && e.Decision == "deny" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected audit event action=rbac.denied resource=bad-role decision=deny, got: %+v", events)
	}
}

// TestRBACAdmissionHandler_AuditWriter_AdmitRBACResource verifies that the handler
// emits action="rbac.admitted" for RBAC resources that are admitted.
func TestRBACAdmissionHandler_AuditWriter_AdmitRBACResource(t *testing.T) {
	aw := &captureWriter{}
	window := NewBootstrapWindow()
	window.Close()

	handler := &RBACAdmissionHandler{
		bootstrapWindow: window,
		namespaceMode:   fixedMode(NamespaceModeEnforce),
		auditWriter:     aw,
	}

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Name:      "owned-role",
			Namespace: "default",
			Kind:      metav1.GroupVersionKind{Kind: "Role"},
			Operation: admissionv1.Create,
			UserInfo:  authv1.UserInfo{Username: "guardian"},
			Object: makeRawRole(t, map[string]string{
				AnnotationRBACOwner: AnnotationRBACOwnerValue,
			}),
		},
	}

	resp := handler.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Errorf("expected Allowed=true for owned resource; got Allowed=false")
	}

	events := aw.written()
	found := false
	for _, e := range events {
		if e.Action == "rbac.admitted" && e.Resource == "owned-role" && e.Decision == "admit" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected audit event action=rbac.admitted resource=owned-role decision=admit, got: %+v", events)
	}
}

// ---------------------------------------------------------------------------
// fixedMode is a NamespaceModeResolver that always returns the given mode.
// ---------------------------------------------------------------------------

type fixedMode NamespaceMode

func (m fixedMode) ResolveMode(_ context.Context, _ string) NamespaceMode {
	return NamespaceMode(m)
}
