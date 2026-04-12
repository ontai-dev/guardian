// Package controller_test covers PermissionSnapshotReconciler behaviour.
//
// Tests use the fake controller-runtime client — no real API server required.
// Each test builds the scheme with guardian v1alpha1 types.
//
// guardian-schema.md §7 PermissionSnapshot, guardian-design.md §1.
package controller_test

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
	seamconditions "github.com/ontai-dev/seam-core/pkg/conditions"
)

// minimalSnapshot returns a PermissionSnapshot with the given name/namespace,
// SnapshotTimestamp set to ts, and FreshnessWindowSeconds set to windowSecs.
func minimalSnapshot(name, ns string, ts time.Time, windowSecs int32) *securityv1alpha1.PermissionSnapshot {
	t := metav1.NewTime(ts)
	return &securityv1alpha1.PermissionSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: securityv1alpha1.PermissionSnapshotSpec{
			TargetCluster:          "ccs-test",
			Version:                ts.UTC().Format(time.RFC3339),
			GeneratedAt:            metav1.NewTime(ts),
			SnapshotTimestamp:      &t,
			FreshnessWindowSeconds: windowSecs,
		},
	}
}

// reconcileSnapshot creates a fake client with the snapshot and reconciles once.
// Returns the updated snapshot from the fake client after reconciliation.
func reconcileSnapshot(
	t *testing.T,
	snapshot *securityv1alpha1.PermissionSnapshot,
	now time.Time,
) (ctrl.Result, *securityv1alpha1.PermissionSnapshot) {
	t.Helper()
	s := buildGuardianScheme()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(snapshot).
		WithStatusSubresource(snapshot).
		Build()

	r := &controller.PermissionSnapshotReconciler{
		Client:   cl,
		Scheme:   s,
		Recorder: record.NewFakeRecorder(16),
		Now:      func() time.Time { return now },
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: snapshot.Name, Namespace: snapshot.Namespace},
	})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	got := &securityv1alpha1.PermissionSnapshot{}
	if err := cl.Get(context.Background(), types.NamespacedName{Name: snapshot.Name, Namespace: snapshot.Namespace}, got); err != nil {
		t.Fatalf("Get PermissionSnapshot after reconcile: %v", err)
	}
	return result, got
}

// TestPermissionSnapshotReconciler_LineageSyncedInitialized verifies that on first
// observation the reconciler writes LineageSynced=False with reason
// LineageControllerAbsent, following the established pattern across all root
// declaration CRDs. seam-core-schema.md §7 Declaration 5.
func TestPermissionSnapshotReconciler_LineageSyncedInitialized(t *testing.T) {
	now := time.Now()
	snapshot := minimalSnapshot("ps-lineage-init", "security-system", now, 300)

	_, got := reconcileSnapshot(t, snapshot, now)

	c := securityv1alpha1.FindCondition(got.Status.Conditions, securityv1alpha1.ConditionTypeLineageSynced)
	if c == nil {
		t.Fatal("LineageSynced condition absent after first reconcile")
	}
	if c.Status != metav1.ConditionFalse {
		t.Errorf("LineageSynced status: got %v; want False", c.Status)
	}
	if c.Reason != securityv1alpha1.ReasonLineageControllerAbsent {
		t.Errorf("LineageSynced reason: got %q; want %q",
			c.Reason, securityv1alpha1.ReasonLineageControllerAbsent)
	}
}

// TestPermissionSnapshotReconciler_FreshSnapshot verifies that a snapshot whose
// SnapshotTimestamp is within FreshnessWindowSeconds of now has Fresh=True with
// reason SnapshotFresh.
func TestPermissionSnapshotReconciler_FreshSnapshot(t *testing.T) {
	now := time.Now()
	// Snapshot is 60 seconds old, window is 300 seconds — should be fresh.
	snapshotTime := now.Add(-60 * time.Second)
	snapshot := minimalSnapshot("ps-fresh", "security-system", snapshotTime, 300)

	_, got := reconcileSnapshot(t, snapshot, now)

	c := securityv1alpha1.FindCondition(got.Status.Conditions, seamconditions.ConditionTypePermissionSnapshotFresh)
	if c == nil {
		t.Fatal("Fresh condition absent after reconcile of fresh snapshot")
	}
	if c.Status != metav1.ConditionTrue {
		t.Errorf("Fresh status: got %v; want True", c.Status)
	}
	if c.Reason != seamconditions.ReasonSnapshotFresh {
		t.Errorf("Fresh reason: got %q; want %q", c.Reason, seamconditions.ReasonSnapshotFresh)
	}
}

// TestPermissionSnapshotReconciler_StaleSnapshot verifies that a snapshot whose
// SnapshotTimestamp is older than FreshnessWindowSeconds has Fresh=False with
// reason SnapshotStale.
func TestPermissionSnapshotReconciler_StaleSnapshot(t *testing.T) {
	now := time.Now()
	// Snapshot is 400 seconds old, window is 300 seconds — should be stale.
	snapshotTime := now.Add(-400 * time.Second)
	snapshot := minimalSnapshot("ps-stale", "security-system", snapshotTime, 300)

	_, got := reconcileSnapshot(t, snapshot, now)

	c := securityv1alpha1.FindCondition(got.Status.Conditions, seamconditions.ConditionTypePermissionSnapshotFresh)
	if c == nil {
		t.Fatal("Fresh condition absent after reconcile of stale snapshot")
	}
	if c.Status != metav1.ConditionFalse {
		t.Errorf("Fresh status: got %v; want False", c.Status)
	}
	if c.Reason != seamconditions.ReasonSnapshotStale {
		t.Errorf("Fresh reason: got %q; want %q", c.Reason, seamconditions.ReasonSnapshotStale)
	}
}

// TestPermissionSnapshotReconciler_RequeuedAfterWindow verifies that the reconciler
// returns a RequeueAfter equal to the spec.FreshnessWindowSeconds so freshness
// is re-evaluated when the snapshot may transition from fresh to stale.
func TestPermissionSnapshotReconciler_RequeuedAfterWindow(t *testing.T) {
	now := time.Now()
	// 60s old, 120s window — fresh now, will be stale at 120s.
	snapshotTime := now.Add(-60 * time.Second)
	snapshot := minimalSnapshot("ps-requeue", "security-system", snapshotTime, 120)

	result, _ := reconcileSnapshot(t, snapshot, now)

	want := 120 * time.Second
	if result.RequeueAfter != want {
		t.Errorf("RequeueAfter: got %v; want %v", result.RequeueAfter, want)
	}
}

// TestPermissionSnapshotReconciler_StaleSnapshotNoRequeue verifies that a stale
// snapshot returns without a RequeueAfter. The EPGReconciler watches for the
// Fresh=False status transition and triggers a full recompute — periodic
// self-requeue from this reconciler would redundantly delay that path.
func TestPermissionSnapshotReconciler_StaleSnapshotNoRequeue(t *testing.T) {
	now := time.Now()
	// 600s old, 300s window — stale.
	snapshotTime := now.Add(-600 * time.Second)
	snapshot := minimalSnapshot("ps-stale-requeue", "security-system", snapshotTime, 300)

	result, _ := reconcileSnapshot(t, snapshot, now)

	if result.RequeueAfter != 0 {
		t.Errorf("RequeueAfter for stale snapshot: got %v; want 0 (no requeue)", result.RequeueAfter)
	}
}

// TestPermissionSnapshotReconciler_LineageSyncedNotOverwrittenOnReconcile verifies
// the one-time write invariant: the reconciler does not overwrite LineageSynced
// if it is already present. This prevents spurious status patches when the
// InfrastructureLineageController has already set it to True.
// seam-core-schema.md §7 Declaration 5.
func TestPermissionSnapshotReconciler_LineageSyncedNotOverwrittenOnReconcile(t *testing.T) {
	now := time.Now()
	snapshot := minimalSnapshot("ps-lineage-noop", "security-system", now, 300)

	// Pre-populate LineageSynced=True as if InfrastructureLineageController already set it.
	snapshot.Status.Conditions = []metav1.Condition{
		{
			Type:               securityv1alpha1.ConditionTypeLineageSynced,
			Status:             metav1.ConditionTrue,
			Reason:             "LineageSynced",
			Message:            "Lineage controller synced.",
			LastTransitionTime: metav1.Now(),
			ObservedGeneration: 1,
		},
	}

	s := buildGuardianScheme()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(snapshot).
		WithStatusSubresource(snapshot).
		Build()

	r := &controller.PermissionSnapshotReconciler{
		Client:   cl,
		Scheme:   s,
		Recorder: record.NewFakeRecorder(16),
		Now:      func() time.Time { return now },
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: snapshot.Name, Namespace: snapshot.Namespace},
	}); err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	got := &securityv1alpha1.PermissionSnapshot{}
	if err := cl.Get(context.Background(), types.NamespacedName{Name: snapshot.Name, Namespace: snapshot.Namespace}, got); err != nil {
		t.Fatalf("Get: %v", err)
	}

	c := securityv1alpha1.FindCondition(got.Status.Conditions, securityv1alpha1.ConditionTypeLineageSynced)
	if c == nil {
		t.Fatal("LineageSynced condition absent after second reconcile")
	}
	if c.Status != metav1.ConditionTrue {
		t.Errorf("LineageSynced was overwritten to %v; expected True to be preserved", c.Status)
	}
}
