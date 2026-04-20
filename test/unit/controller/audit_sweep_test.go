// Package controller_test -- AC-3 guardian audit sweep acceptance contract tests.
//
// AC-3: Every critical guardian controller action must produce a correctly
// structured audit event via AuditWriter. LazyAuditWriter must drop events
// silently when CNPG is unavailable and forward them once the database is ready.
//
// Tests:
//   1. LazyAuditWriter drops events and returns nil when ErrDatabaseNotReady.
//   2. LazyAuditWriter forwards events to the real database after Set is called.
//   3. BootstrapAnnotationRunnable.Start emits bootstrap.annotation_sweep_complete.
//   4. RBACPolicyReconciler emits rbacpolicy.validated on a valid policy.
//
// guardian-schema.md §16. G-BL-SELF-AUDIT-MISSING investigation.
package controller_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	clientevents "k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
	"github.com/ontai-dev/guardian/internal/database"
)

// ---------------------------------------------------------------------------
// captureAuditWriter records Write calls for AC-3 assertions.
// Defined here to avoid redeclaration conflicts with audit_writer_test.go
// (testAuditWriter is already declared there).
// ---------------------------------------------------------------------------

type ac3AuditWriter struct {
	mu     sync.Mutex
	events []database.AuditEvent
}

func (w *ac3AuditWriter) Write(_ context.Context, event database.AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, event)
	return nil
}

func (w *ac3AuditWriter) written() []database.AuditEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]database.AuditEvent, len(w.events))
	copy(out, w.events)
	return out
}

func (w *ac3AuditWriter) hasAction(action string) bool {
	for _, e := range w.written() {
		if e.Action == action {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// mockAuditDatabase is a simple in-memory AuditDatabase for LazyAuditWriter tests.
// ---------------------------------------------------------------------------

type mockAuditDatabase struct {
	mu     sync.Mutex
	events []database.AuditEvent
}

func (m *mockAuditDatabase) EventExists(_ context.Context, _ string, _ int64) (bool, error) {
	return false, nil
}

func (m *mockAuditDatabase) InsertEvent(_ context.Context, event database.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *mockAuditDatabase) written() []database.AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]database.AuditEvent, len(m.events))
	copy(out, m.events)
	return out
}

// ---------------------------------------------------------------------------
// Test 1 -- LazyAuditWriter drops events when database not ready
// ---------------------------------------------------------------------------

// TestAC3_LazyAuditWriter_DropsEventsWhenNotReady verifies that LazyAuditWriter
// returns nil (non-blocking) when ErrDatabaseNotReady, so reconcilers are not
// interrupted by pre-CNPG audit writes.
// AC-3 gate: audit drop must not block reconciliation. guardian-schema.md §16.
func TestAC3_LazyAuditWriter_DropsEventsWhenNotReady(t *testing.T) {
	lazy := database.NewLazyAuditDatabase()
	w := database.NewLazyAuditWriter(lazy)

	err := w.Write(context.Background(), database.AuditEvent{
		ClusterID: "management",
		Subject:   "guardian",
		Action:    "rbacprofile.provisioned",
		Resource:  "test-profile",
		Decision:  "system",
	})
	if err != nil {
		t.Errorf("AC-3: LazyAuditWriter.Write must return nil when database not ready, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 2 -- LazyAuditWriter forwards events after Set
// ---------------------------------------------------------------------------

// TestAC3_LazyAuditWriter_ForwardsEventsAfterSet verifies that once
// LazyAuditDatabase.Set is called with a real database, subsequent Write calls
// are forwarded to that database. This is the post-CNPG-ready path.
// AC-3 gate: audit events reach storage once CNPG is ready. guardian-schema.md §16.
func TestAC3_LazyAuditWriter_ForwardsEventsAfterSet(t *testing.T) {
	lazy := database.NewLazyAuditDatabase()
	mock := &mockAuditDatabase{}
	lazy.Set(mock)

	w := database.NewLazyAuditWriter(lazy)
	event := database.AuditEvent{
		ClusterID: "management",
		Subject:   "guardian",
		Action:    "rbacprofile.provisioned",
		Resource:  "test-profile",
		Decision:  "system",
	}
	if err := w.Write(context.Background(), event); err != nil {
		t.Fatalf("AC-3: LazyAuditWriter.Write returned error after Set: %v", err)
	}

	stored := mock.written()
	found := false
	for _, e := range stored {
		if e.Action == "rbacprofile.provisioned" && e.Resource == "test-profile" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("AC-3: LazyAuditWriter did not forward event to database after Set; stored=%+v", stored)
	}
}

// ---------------------------------------------------------------------------
// Test 3 -- BootstrapAnnotationRunnable.Start emits bootstrap.annotation_sweep_complete
// ---------------------------------------------------------------------------

// buildSweepSchemeAC3 returns a scheme with core and guardian types. Parallel
// to buildSweepScheme in bootstrap_annotation_test.go but named differently to
// avoid redeclaration.
func buildSweepSchemeAC3(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(securityv1alpha1.AddToScheme(s))
	return s
}

// TestAC3_BootstrapSweep_EmitsAnnotationSweepCompleteAuditEvent verifies that
// BootstrapAnnotationRunnable.Start calls AuditWriter.Write with
// action="bootstrap.annotation_sweep_complete" after the sweep finishes.
// AC-3 gate: sweep audit emission contract. guardian-schema.md §4, §16.
func TestAC3_BootstrapSweep_EmitsAnnotationSweepCompleteAuditEvent(t *testing.T) {
	s := buildSweepSchemeAC3(t)
	c := fake.NewClientBuilder().WithScheme(s).Build()
	done := &atomic.Bool{}
	aw := &ac3AuditWriter{}

	runnable := &controller.BootstrapAnnotationRunnable{
		Client:      c,
		SweepDone:   done,
		AuditWriter: aw,
	}

	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("AC-3: BootstrapAnnotationRunnable.Start returned error: %v", err)
	}

	if !aw.hasAction("bootstrap.annotation_sweep_complete") {
		t.Errorf("AC-3: expected audit event bootstrap.annotation_sweep_complete after sweep; got: %+v", aw.written())
	}
}

// ---------------------------------------------------------------------------
// Test 4 -- RBACPolicyReconciler emits rbacpolicy.validated
// ---------------------------------------------------------------------------

// TestAC3_RBACPolicyReconciler_EmitsValidatedAuditEvent verifies that
// RBACPolicyReconciler calls AuditWriter.Write with action="rbacpolicy.validated"
// when a valid RBACPolicy is reconciled. This is the action recorded in the
// backlog item G-BL-SELF-AUDIT-MISSING as potentially dropped.
// AC-3 gate: rbacpolicy.validated audit emission contract. guardian-schema.md §7, §16.
func TestAC3_RBACPolicyReconciler_EmitsValidatedAuditEvent(t *testing.T) {
	const ns = "seam-system"
	ps := minimalPermissionSet("exec-ps-ac3", ns)
	policy := &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy-ac3", Namespace: ns},
		Spec: securityv1alpha1.RBACPolicySpec{
			SubjectScope:            securityv1alpha1.SubjectScopePlatform,
			EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
			AllowedClusters:         []string{"ccs-dev"},
			MaximumPermissionSetRef: "exec-ps-ac3",
		},
	}

	s := buildGuardianScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(policy, ps).
		WithStatusSubresource(policy).
		Build()

	aw := &ac3AuditWriter{}
	r := &controller.RBACPolicyReconciler{
		Client:      c,
		Scheme:      s,
		Recorder:    clientevents.NewFakeRecorder(16),
		AuditWriter: aw,
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-policy-ac3", Namespace: ns}}
	ctx := context.Background()

	// First reconcile adds the finalizer.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("AC-3: first Reconcile returned error: %v", err)
	}
	// Second reconcile performs validation.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("AC-3: second Reconcile returned error: %v", err)
	}

	if !aw.hasAction("rbacpolicy.validated") {
		t.Errorf("AC-3: expected audit event rbacpolicy.validated; got: %+v", aw.written())
	}
}
