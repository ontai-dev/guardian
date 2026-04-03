// Package controller_test contains unit tests for drift computation logic.
//
// These tests cover ComputeDrift and ReconcileAllDrift — pure functions with no
// Kubernetes API calls. All edge cases in drift semantics are verified here.
package controller_test

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
)

// --- ComputeDrift tests ---

// Test 1 — Empty expectedVersion: not drifted.
// An unset expectedVersion means no snapshot has been generated yet.
func TestComputeDrift_EmptyExpectedVersion_NotDrifted(t *testing.T) {
	isDrifted, reason := controller.ComputeDrift("", "some-acked-version")
	if isDrifted {
		t.Error("expected IsDrifted=false when expectedVersion is empty")
	}
	if !strings.Contains(reason, "no expected version") {
		t.Errorf("expected reason to contain 'no expected version'; got %q", reason)
	}
}

// Test 2 — Empty lastAckedVersion: drifted.
// A snapshot exists but has never been acknowledged by the target cluster agent.
func TestComputeDrift_EmptyLastAckedVersion_Drifted(t *testing.T) {
	isDrifted, reason := controller.ComputeDrift("2026-03-30T12:00:00Z", "")
	if !isDrifted {
		t.Error("expected IsDrifted=true when lastAckedVersion is empty")
	}
	if !strings.Contains(reason, "no acknowledgement") {
		t.Errorf("expected reason to contain 'no acknowledgement'; got %q", reason)
	}
}

// Test 3 — Matching versions: not drifted. Reason is empty string.
func TestComputeDrift_MatchingVersions_NotDrifted(t *testing.T) {
	version := "2026-03-30T12:00:00Z"
	isDrifted, reason := controller.ComputeDrift(version, version)
	if isDrifted {
		t.Error("expected IsDrifted=false when versions match")
	}
	if reason != "" {
		t.Errorf("expected empty reason when not drifted; got %q", reason)
	}
}

// Test 4 — Mismatched versions: drifted. Reason contains both version strings.
func TestComputeDrift_MismatchedVersions_Drifted(t *testing.T) {
	expected := "2026-03-30T12:00:00Z"
	lastAcked := "2026-03-29T10:00:00Z"
	isDrifted, reason := controller.ComputeDrift(expected, lastAcked)
	if !isDrifted {
		t.Error("expected IsDrifted=true when versions differ")
	}
	if !strings.Contains(reason, expected) {
		t.Errorf("expected reason to contain expected version %q; got %q", expected, reason)
	}
	if !strings.Contains(reason, lastAcked) {
		t.Errorf("expected reason to contain lastAcked version %q; got %q", lastAcked, reason)
	}
}

// Test 5 — Both empty: not drifted.
// Empty expectedVersion takes precedence — no snapshot generated yet.
func TestComputeDrift_BothEmpty_NotDrifted(t *testing.T) {
	isDrifted, reason := controller.ComputeDrift("", "")
	if isDrifted {
		t.Error("expected IsDrifted=false when both versions are empty")
	}
	if !strings.Contains(reason, "no expected version") {
		t.Errorf("expected reason to contain 'no expected version'; got %q", reason)
	}
}

// Test 6 — Valid RFC3339 matching versions: plain string comparison, not timestamp arithmetic.
func TestComputeDrift_RFC3339MatchingVersions_NotDrifted(t *testing.T) {
	// Same RFC3339 string, identical bytes — should be not drifted regardless of
	// timestamp semantics. ComputeDrift performs strict string equality.
	version := "2026-03-30T12:00:00Z"
	isDrifted, _ := controller.ComputeDrift(version, version)
	if isDrifted {
		t.Error("expected IsDrifted=false for identical RFC3339 strings")
	}
}

// Test 7 — Versions differing only by trailing whitespace: drifted.
// ComputeDrift performs strict string equality. Whitespace variants are different versions.
func TestComputeDrift_TrailingWhitespaceDifference_Drifted(t *testing.T) {
	expected := "2026-03-30T12:00:00Z"
	lastAcked := "2026-03-30T12:00:00Z " // trailing space
	isDrifted, _ := controller.ComputeDrift(expected, lastAcked)
	if !isDrifted {
		t.Error("expected IsDrifted=true when versions differ by trailing whitespace")
	}
}

// --- ReconcileAllDrift tests ---

// makeSnapshot constructs a minimal PermissionSnapshot for testing.
func makeSnapshot(name, cluster, expectedVersion, lastAckedVersion string, currentDrift bool) securityv1alpha1.PermissionSnapshot {
	return securityv1alpha1.PermissionSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "security-system"},
		Spec: securityv1alpha1.PermissionSnapshotSpec{
			TargetCluster: cluster,
		},
		Status: securityv1alpha1.PermissionSnapshotStatus{
			ExpectedVersion:  expectedVersion,
			LastAckedVersion: lastAckedVersion,
			Drift:            currentDrift,
		},
	}
}

// Test 8 — Empty snapshot slice returns non-nil empty slice.
func TestReconcileAllDrift_EmptyInput_ReturnsEmptyNonNil(t *testing.T) {
	results := controller.ReconcileAllDrift([]securityv1alpha1.PermissionSnapshot{})
	if results == nil {
		t.Error("expected non-nil slice for empty input; got nil")
	}
	if len(results) != 0 {
		t.Errorf("expected empty slice; got %d entries", len(results))
	}
}

// Test 9 — Single snapshot with matching versions: IsDrifted=false.
func TestReconcileAllDrift_SingleMatchingSnapshot_NotDrifted(t *testing.T) {
	version := "2026-03-30T12:00:00Z"
	snapshots := []securityv1alpha1.PermissionSnapshot{
		makeSnapshot("snap-ccs-test", "ccs-test", version, version, true),
	}
	results := controller.ReconcileAllDrift(snapshots)
	if len(results) != 1 {
		t.Fatalf("expected 1 result; got %d", len(results))
	}
	if results[0].IsDrifted {
		t.Error("expected IsDrifted=false for matching versions")
	}
	if results[0].SnapshotName != "snap-ccs-test" {
		t.Errorf("expected SnapshotName=snap-ccs-test; got %q", results[0].SnapshotName)
	}
	if results[0].ClusterName != "ccs-test" {
		t.Errorf("expected ClusterName=ccs-test; got %q", results[0].ClusterName)
	}
}

// Test 10 — Single snapshot with empty LastAckedVersion: IsDrifted=true.
func TestReconcileAllDrift_SingleSnapshotEmptyAck_Drifted(t *testing.T) {
	snapshots := []securityv1alpha1.PermissionSnapshot{
		makeSnapshot("snap-ccs-dev", "ccs-dev", "2026-03-30T12:00:00Z", "", false),
	}
	results := controller.ReconcileAllDrift(snapshots)
	if len(results) != 1 {
		t.Fatalf("expected 1 result; got %d", len(results))
	}
	if !results[0].IsDrifted {
		t.Error("expected IsDrifted=true when LastAckedVersion is empty")
	}
}

// Test 11 — Three snapshots: one matching, one mismatched, one with empty LastAckedVersion.
func TestReconcileAllDrift_ThreeSnapshots_IndependentResults(t *testing.T) {
	snapshots := []securityv1alpha1.PermissionSnapshot{
		makeSnapshot("snap-a", "cluster-a", "v1", "v1", false),  // matching
		makeSnapshot("snap-b", "cluster-b", "v2", "v1", false),  // mismatched
		makeSnapshot("snap-c", "cluster-c", "v3", "", false),    // never acked
	}
	results := controller.ReconcileAllDrift(snapshots)
	if len(results) != 3 {
		t.Fatalf("expected 3 results; got %d", len(results))
	}
	// snap-a: not drifted
	if results[0].IsDrifted {
		t.Errorf("snap-a: expected IsDrifted=false; got true")
	}
	// snap-b: drifted (v2 vs v1)
	if !results[1].IsDrifted {
		t.Errorf("snap-b: expected IsDrifted=true; got false")
	}
	// snap-c: drifted (never acknowledged)
	if !results[2].IsDrifted {
		t.Errorf("snap-c: expected IsDrifted=true (no ack); got false")
	}
}

// Test 12 — Snapshot with empty ExpectedVersion and non-empty LastAckedVersion: not drifted.
// No expected version means no snapshot has been generated yet — not a drift condition,
// even if an old version was previously acknowledged.
func TestReconcileAllDrift_EmptyExpectedNonEmptyAck_NotDrifted(t *testing.T) {
	snapshots := []securityv1alpha1.PermissionSnapshot{
		makeSnapshot("snap-stale", "ccs-test", "", "2026-03-29T10:00:00Z", true),
	}
	results := controller.ReconcileAllDrift(snapshots)
	if len(results) != 1 {
		t.Fatalf("expected 1 result; got %d", len(results))
	}
	if results[0].IsDrifted {
		t.Error("expected IsDrifted=false when expectedVersion is empty, regardless of lastAckedVersion")
	}
}
