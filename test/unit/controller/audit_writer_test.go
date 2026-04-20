// Package controller_test verifies that reconcilers write audit events via AuditWriter.
//
// Tests:
//  1. RBACProfileReconciler calls AuditWriter.Write with action="rbacprofile.provisioned"
//     when provisioning succeeds.
//  2. NoopAuditWriter discards events and returns nil — safe for all existing unit tests.
//
// guardian-schema.md §16.
package controller_test

import (
	"context"
	"sync"
	"testing"

	"k8s.io/apimachinery/pkg/types"
	clientevents "k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
	"github.com/ontai-dev/guardian/internal/database"
)

// ---------------------------------------------------------------------------
// testAuditWriter captures Write calls for assertion.
// ---------------------------------------------------------------------------

// testAuditWriter records every AuditEvent written to it. Thread-safe.
type testAuditWriter struct {
	mu     sync.Mutex
	events []database.AuditEvent
}

func (w *testAuditWriter) Write(_ context.Context, event database.AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, event)
	return nil
}

func (w *testAuditWriter) written() []database.AuditEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]database.AuditEvent, len(w.events))
	copy(out, w.events)
	return out
}

// ---------------------------------------------------------------------------
// Helpers — minimal provisioned profile fixture
// ---------------------------------------------------------------------------

// provisionedFixture returns a pre-populated set of objects that will result
// in provisioned=true: a valid RBACPolicy with a matching PermissionSet, and
// an RBACProfile that satisfies all checks.
// Uses the same structure as makePolicyForProvisioning/makeProfileForProvisioning
// to ensure compliance checks pass.
func provisionedFixture(t *testing.T) (
	*securityv1alpha1.RBACProfile,
	*securityv1alpha1.RBACPolicy,
	*securityv1alpha1.PermissionSet,
) {
	t.Helper()
	ns := "seam-system"
	ps := makePermissionSetForProvisioning("exec-ps", ns)
	policy := makePolicyForProvisioning("test-policy", ns)
	profile := makeProfileForProvisioning("test-profile", ns,
		"system:serviceaccount:seam-system:test-sa",
		"test-policy", "exec-ps")
	return profile, policy, ps
}

// ---------------------------------------------------------------------------
// WS3 Test 1 — RBACProfileReconciler calls AuditWriter.Write on provisioning success
// ---------------------------------------------------------------------------

func TestRBACProfileReconciler_AuditWriterCalledOnProvisionSuccess(t *testing.T) {
	profile, policy, ps := provisionedFixture(t)

	s := buildProvisioningScheme(t)
	// Note: WithStatusSubresource only for RBACProfile — the policy status is pre-populated
	// in the fixture and must not be stripped by the subresource handler.
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(profile, policy, ps).
		WithStatusSubresource(&securityv1alpha1.RBACProfile{}).
		Build()

	aw := &testAuditWriter{}
	r := &controller.RBACProfileReconciler{
		Client:      c,
		Scheme:      s,
		Recorder:    clientevents.NewFakeRecorder(32),
		AuditWriter: aw,
	}

	const ns = "seam-system"
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-profile", Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	events := aw.written()
	found := false
	for _, e := range events {
		if e.Action == "rbacprofile.provisioned" && e.Resource == "test-profile" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected audit event action=rbacprofile.provisioned resource=test-profile, got events: %+v", events)
	}
}

// ---------------------------------------------------------------------------
// WS3 Test 2 — NoopAuditWriter discards events silently
// ---------------------------------------------------------------------------

func TestNoopAuditWriter_DiscardsSilently(t *testing.T) {
	noop := database.NoopAuditWriter{}
	err := noop.Write(context.Background(), database.AuditEvent{
		ClusterID:      "management",
		Subject:        "guardian",
		Action:         "rbacpolicy.validated",
		Resource:       "test-policy",
		Decision:       "system",
		MatchedPolicy:  "ValidationPassed",
		SequenceNumber: 1,
	})
	if err != nil {
		t.Errorf("NoopAuditWriter.Write returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// WS3 Test 3 — Existing reconcilers with nil AuditWriter do not panic
// ---------------------------------------------------------------------------

// TestRBACProfileReconciler_NilAuditWriterDoesNotPanic verifies that all existing
// unit tests that construct RBACProfileReconciler without an AuditWriter continue
// to work — the nil AuditWriter is treated as a no-op, not a nil dereference.
func TestRBACProfileReconciler_NilAuditWriterDoesNotPanic(t *testing.T) {
	profile, policy, ps := provisionedFixture(t)

	const ns = "seam-system"
	s := buildProvisioningScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(profile, policy, ps).
		WithStatusSubresource(&securityv1alpha1.RBACProfile{}).
		Build()

	r := &controller.RBACProfileReconciler{
		Client:   c,
		Scheme:   s,
		Recorder: clientevents.NewFakeRecorder(32),
		// AuditWriter intentionally left nil — matches existing test construction.
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-profile", Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile with nil AuditWriter returned error: %v", err)
	}
}
