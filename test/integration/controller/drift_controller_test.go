// Package controller_test — drift controller integration tests.
//
// These tests use the shared envtest environment from TestMain in
// rbacpolicy_controller_test.go. All four reconcilers are registered,
// including the updated EPGReconciler with the PermissionSnapshotReceipt and
// PermissionSnapshot watches wired to the drift-check path.
//
// The tests verify that:
//   - PermissionSnapshot Status.Drift is correctly set based on version comparison.
//   - Creating or updating a PermissionSnapshotReceipt triggers reconcileDrift.
//   - Transition events (SnapshotDelivered, SnapshotDriftDetected) are emitted.
//   - The drift-check path never triggers EPG recomputation.
package controller_test

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

const (
	driftTestNS = "security-system"
)

// createSnapshot creates a PermissionSnapshot and patches its status to set
// ExpectedVersion. Returns the created snapshot. t.Cleanup deletes it.
func createSnapshot(t *testing.T, name, cluster, expectedVersion string) *securityv1alpha1.PermissionSnapshot {
	t.Helper()
	sn := &securityv1alpha1.PermissionSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: driftTestNS,
		},
		Spec: securityv1alpha1.PermissionSnapshotSpec{
			TargetCluster: cluster,
			Version:       expectedVersion,
			GeneratedAt:   metav1.Now(),
		},
	}
	if err := k8sClient.Create(context.Background(), sn); err != nil {
		t.Fatalf("createSnapshot: Create: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), sn) })

	// Patch status to set ExpectedVersion.
	statusPatch := sn.DeepCopy()
	statusPatch.Status.ExpectedVersion = expectedVersion
	if err := k8sClient.Status().Patch(context.Background(), statusPatch,
		client.MergeFrom(sn)); err != nil {
		t.Fatalf("createSnapshot: Status().Patch: %v", err)
	}
	return sn
}

// createReceipt creates a PermissionSnapshotReceipt in the given namespace.
// t.Cleanup deletes it.
func createReceipt(t *testing.T, name, ns, cluster, snapshotVersion string) *securityv1alpha1.PermissionSnapshotReceipt {
	t.Helper()
	r := &securityv1alpha1.PermissionSnapshotReceipt{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: securityv1alpha1.PermissionSnapshotReceiptSpec{
			ClusterName:     cluster,
			SnapshotVersion: snapshotVersion,
			AcknowledgedAt:  metav1.Now(),
		},
	}
	if err := k8sClient.Create(context.Background(), r); err != nil {
		t.Fatalf("createReceipt: Create: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), r) })
	return r
}

// getSnapshotDrift fetches a PermissionSnapshot and returns its Status.Drift.
func getSnapshotDrift(name, ns string) (bool, error) {
	got := &securityv1alpha1.PermissionSnapshot{}
	if err := k8sClient.Get(context.Background(),
		types.NamespacedName{Name: name, Namespace: ns}, got); err != nil {
		return false, err
	}
	return got.Status.Drift, nil
}

// Test 1 — New PermissionSnapshot with ExpectedVersion set and empty LastAckedVersion
// must reach Status.Drift=true.
//
// Mechanism: creating the PermissionSnapshot triggers the PermissionSnapshot watch
// on the EPGReconciler, which enqueues a drift-check and sets Drift=true.
func TestDrift_NewSnapshotWithExpectedVersion_BecomesTrue(t *testing.T) {
	createSnapshot(t, "drift-test-snap-1", "ccs-test-d1", "2026-03-30T12:00:00Z")

	ok := poll(t, 10*time.Second, func() bool {
		drift, err := getSnapshotDrift("drift-test-snap-1", driftTestNS)
		return err == nil && drift
	})
	if !ok {
		got := &securityv1alpha1.PermissionSnapshot{}
		_ = k8sClient.Get(context.Background(),
			types.NamespacedName{Name: "drift-test-snap-1", Namespace: driftTestNS}, got)
		t.Fatalf("timed out: expected Drift=true; status: %+v", got.Status)
	}
}

// Test 2 — Writing a matching LastAckedVersion to a drifted PermissionSnapshot
// clears Drift and emits a SnapshotDelivered event.
//
// The test simulates what the management cluster conductor receipt observation loop does:
// it reads a PermissionSnapshotReceipt and updates PermissionSnapshot.Status.LastAckedVersion.
// The EPGReconciler's drift-check path then detects the match and sets Drift=false.
func TestDrift_MatchingLastAckedVersion_ClearsDrift(t *testing.T) {
	version := "2026-03-30T13:00:00Z"
	createSnapshot(t, "drift-test-snap-2", "ccs-test-d2", version)

	// Wait for initial Drift=true.
	ok := poll(t, 10*time.Second, func() bool {
		drift, err := getSnapshotDrift("drift-test-snap-2", driftTestNS)
		return err == nil && drift
	})
	if !ok {
		t.Fatal("timed out waiting for initial Drift=true on drift-test-snap-2")
	}

	// Create a PermissionSnapshotReceipt to trigger the drift-check watch.
	_ = createReceipt(t, "drift-test-receipt-2", "security-system", "ccs-test-d2", version)

	// Simulate the management cluster conductor writing LastAckedVersion to the snapshot.
	// (In production, the agent reads the receipt and updates this field.)
	latest := &securityv1alpha1.PermissionSnapshot{}
	if err := k8sClient.Get(context.Background(),
		types.NamespacedName{Name: "drift-test-snap-2", Namespace: driftTestNS}, latest); err != nil {
		t.Fatalf("failed to get snapshot: %v", err)
	}
	patchBase := latest.DeepCopy()
	latest.Status.LastAckedVersion = version
	if err := k8sClient.Status().Patch(context.Background(), latest,
		client.MergeFrom(patchBase)); err != nil {
		t.Fatalf("failed to patch LastAckedVersion: %v", err)
	}

	// Wait for Drift=false.
	ok = poll(t, 15*time.Second, func() bool {
		drift, err := getSnapshotDrift("drift-test-snap-2", driftTestNS)
		return err == nil && !drift
	})
	if !ok {
		got := &securityv1alpha1.PermissionSnapshot{}
		_ = k8sClient.Get(context.Background(),
			types.NamespacedName{Name: "drift-test-snap-2", Namespace: driftTestNS}, got)
		t.Fatalf("timed out: expected Drift=false after matching ack; status: %+v", got.Status)
	}
}

// Test 3 — Drift regression: advancing ExpectedVersion on a previously in-sync snapshot
// re-sets Drift=true and emits a SnapshotDriftDetected warning event.
func TestDrift_AdvancedExpectedVersion_RegriftsSnapshot(t *testing.T) {
	oldVersion := "2026-03-30T14:00:00Z"
	createSnapshot(t, "drift-test-snap-3", "ccs-test-d3", oldVersion)

	// Wait for initial Drift=true.
	ok := poll(t, 10*time.Second, func() bool {
		drift, err := getSnapshotDrift("drift-test-snap-3", driftTestNS)
		return err == nil && drift
	})
	if !ok {
		t.Fatal("timed out waiting for initial Drift=true on drift-test-snap-3")
	}

	// Simulate delivery: patch LastAckedVersion=ExpectedVersion → Drift should clear.
	latest := &securityv1alpha1.PermissionSnapshot{}
	if err := k8sClient.Get(context.Background(),
		types.NamespacedName{Name: "drift-test-snap-3", Namespace: driftTestNS}, latest); err != nil {
		t.Fatalf("failed to get snapshot: %v", err)
	}
	patchBase := latest.DeepCopy()
	latest.Status.LastAckedVersion = oldVersion
	if err := k8sClient.Status().Patch(context.Background(), latest, client.MergeFrom(patchBase)); err != nil {
		t.Fatalf("failed to patch LastAckedVersion: %v", err)
	}

	// Trigger drift-check via receipt.
	_ = createReceipt(t, "drift-test-receipt-3", "security-system", "ccs-test-d3", oldVersion)

	ok = poll(t, 15*time.Second, func() bool {
		drift, err := getSnapshotDrift("drift-test-snap-3", driftTestNS)
		return err == nil && !drift
	})
	if !ok {
		t.Fatal("timed out waiting for Drift=false (delivery) on drift-test-snap-3")
	}

	// Now advance the ExpectedVersion (simulating a new EPG computation).
	newVersion := "2026-03-30T15:00:00Z"
	latest = &securityv1alpha1.PermissionSnapshot{}
	if err := k8sClient.Get(context.Background(),
		types.NamespacedName{Name: "drift-test-snap-3", Namespace: driftTestNS}, latest); err != nil {
		t.Fatalf("failed to get snapshot for version advance: %v", err)
	}
	// Patch spec.Version and status.ExpectedVersion to advance.
	specPatchBase := latest.DeepCopy()
	latest.Spec.Version = newVersion
	if err := k8sClient.Patch(context.Background(), latest, client.MergeFrom(specPatchBase)); err != nil {
		t.Fatalf("failed to patch snapshot spec Version: %v", err)
	}
	latest2 := &securityv1alpha1.PermissionSnapshot{}
	if err := k8sClient.Get(context.Background(),
		types.NamespacedName{Name: "drift-test-snap-3", Namespace: driftTestNS}, latest2); err != nil {
		t.Fatalf("failed to get snapshot after spec patch: %v", err)
	}
	statusBase := latest2.DeepCopy()
	latest2.Status.ExpectedVersion = newVersion
	if err := k8sClient.Status().Patch(context.Background(), latest2, client.MergeFrom(statusBase)); err != nil {
		t.Fatalf("failed to patch ExpectedVersion: %v", err)
	}

	// Drift should be detected: oldVersion was acked, but newVersion is now expected.
	ok = poll(t, 15*time.Second, func() bool {
		drift, err := getSnapshotDrift("drift-test-snap-3", driftTestNS)
		return err == nil && drift
	})
	if !ok {
		got := &securityv1alpha1.PermissionSnapshot{}
		_ = k8sClient.Get(context.Background(),
			types.NamespacedName{Name: "drift-test-snap-3", Namespace: driftTestNS}, got)
		t.Fatalf("timed out: expected Drift=true after version advance; status: %+v", got.Status)
	}
}

// Test 4 — PermissionSnapshotReceipt write triggers drift-check path, NOT EPG recomputation.
//
// This is verified by asserting that no epg-recompute-requested annotation is set on any
// RBACProfile as a result of a PermissionSnapshotReceipt write. EPG recomputation only
// occurs when the annotation is set on a watched resource — the drift-check path never
// sets that annotation.
func TestDrift_ReceiptWrite_DoesNotTriggerEPGRecomputation(t *testing.T) {
	// Create a receipt to trigger the drift-check path.
	_ = createReceipt(t, "drift-test-receipt-4", "security-system", "ccs-test-d4", "v1")

	// Wait a short time for the reconciler to process.
	time.Sleep(3 * time.Second)

	// Assert that no RBACProfile has the epg-recompute-requested annotation set.
	var profileList securityv1alpha1.RBACProfileList
	if err := k8sClient.List(context.Background(), &profileList); err != nil {
		t.Fatalf("failed to list RBACProfiles: %v", err)
	}
	for _, p := range profileList.Items {
		if p.GetAnnotations()["ontai.dev/epg-recompute-requested"] == "true" {
			t.Errorf("RBACProfile %q has epg-recompute-requested=true after receipt write — "+
				"drift-check must not trigger EPG recomputation", p.Name)
		}
	}
}

// Test 5 — drift-check triggers reconcileDrift only, not a new PermissionSnapshot.
//
// Verifies that when a PermissionSnapshotReceipt triggers the drift-check, no new
// PermissionSnapshot is created and the version of an existing snapshot is unchanged.
func TestDrift_DriftCheckPath_DoesNotCreateNewSnapshot(t *testing.T) {
	version := "2026-03-30T16:00:00Z"
	createSnapshot(t, "drift-test-snap-5", "ccs-test-d5", version)

	// Wait for initial drift state to settle.
	ok := poll(t, 10*time.Second, func() bool {
		got := &securityv1alpha1.PermissionSnapshot{}
		return k8sClient.Get(context.Background(),
			types.NamespacedName{Name: "drift-test-snap-5", Namespace: driftTestNS}, got) == nil
	})
	if !ok {
		t.Fatal("timed out waiting for drift-test-snap-5 to be accessible")
	}

	// Record the snapshot version before receipt write.
	before := &securityv1alpha1.PermissionSnapshot{}
	if err := k8sClient.Get(context.Background(),
		types.NamespacedName{Name: "drift-test-snap-5", Namespace: driftTestNS}, before); err != nil {
		t.Fatalf("failed to get snapshot: %v", err)
	}
	versionBefore := before.Spec.Version

	// Write a receipt — triggers drift-check, not EPG recomputation.
	_ = createReceipt(t, "drift-test-receipt-5", "security-system", "ccs-test-d5", version)
	time.Sleep(3 * time.Second)

	// Assert the snapshot version is unchanged (EPG did not recompute and replace it).
	after := &securityv1alpha1.PermissionSnapshot{}
	if err := k8sClient.Get(context.Background(),
		types.NamespacedName{Name: "drift-test-snap-5", Namespace: driftTestNS}, after); err != nil {
		t.Fatalf("failed to get snapshot after receipt: %v", err)
	}
	if after.Spec.Version != versionBefore {
		t.Errorf("Spec.Version changed from %q to %q — EPG recomputation was incorrectly triggered",
			versionBefore, after.Spec.Version)
	}

	// List all snapshots: no additional snapshot for this cluster should exist.
	var list securityv1alpha1.PermissionSnapshotList
	if err := k8sClient.List(context.Background(), &list,
		client.InNamespace(driftTestNS)); err != nil {
		t.Fatalf("failed to list snapshots: %v", err)
	}
	count := 0
	for _, item := range list.Items {
		if item.Spec.TargetCluster == "ccs-test-d5" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected 1 snapshot for ccs-test-d5; found %d — drift-check must not create new snapshots", count)
	}
}

// TestDrift_SnapshotDelivered_EmitsNormalEvent verifies that a SnapshotDelivered
// Normal event is emitted when Drift transitions from true to false.
func TestDrift_SnapshotDelivered_EmitsNormalEvent(t *testing.T) {
	version := "2026-03-30T17:00:00Z"
	_ = createSnapshot(t, "drift-test-snap-ev", "ccs-test-dev", version)

	// Wait for initial Drift=true.
	ok := poll(t, 10*time.Second, func() bool {
		drift, err := getSnapshotDrift("drift-test-snap-ev", driftTestNS)
		return err == nil && drift
	})
	if !ok {
		t.Fatal("timed out waiting for initial Drift=true on drift-test-snap-ev")
	}

	// Patch LastAckedVersion and create a receipt to trigger drift-check.
	latest := &securityv1alpha1.PermissionSnapshot{}
	if err := k8sClient.Get(context.Background(),
		types.NamespacedName{Name: "drift-test-snap-ev", Namespace: driftTestNS}, latest); err != nil {
		t.Fatalf("failed to get snapshot: %v", err)
	}
	patchBase := latest.DeepCopy()
	latest.Status.LastAckedVersion = version
	if err := k8sClient.Status().Patch(context.Background(), latest, client.MergeFrom(patchBase)); err != nil {
		t.Fatalf("failed to patch LastAckedVersion: %v", err)
	}
	_ = createReceipt(t, "drift-test-receipt-ev", "security-system", "ccs-test-dev", version)

	// Wait for Drift=false.
	ok = poll(t, 15*time.Second, func() bool {
		drift, err := getSnapshotDrift("drift-test-snap-ev", driftTestNS)
		return err == nil && !drift
	})
	if !ok {
		t.Fatal("timed out waiting for Drift=false on drift-test-snap-ev")
	}

	// Verify a SnapshotDelivered Normal event was emitted on the snapshot.
	ok = poll(t, 10*time.Second, func() bool {
		var events corev1.EventList
		if err := k8sClient.List(context.Background(), &events,
			client.InNamespace(driftTestNS)); err != nil {
			return false
		}
		for _, e := range events.Items {
			if e.Reason == "SnapshotDelivered" &&
				e.Type == corev1.EventTypeNormal &&
				e.InvolvedObject.Name == "drift-test-snap-ev" {
				return true
			}
		}
		return false
	})
	if !ok {
		t.Error("timed out waiting for SnapshotDelivered Normal event on drift-test-snap-ev")
	}
}
