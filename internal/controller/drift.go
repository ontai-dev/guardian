package controller

import (
	"fmt"

	securityv1alpha1 "github.com/ontai-dev/ont-security/api/v1alpha1"
)

// DriftResult is the computed drift state for a single PermissionSnapshot.
// Produced by ReconcileAllDrift and consumed by the reconcileDrift method.
type DriftResult struct {
	// SnapshotName is the Kubernetes object name of the PermissionSnapshot.
	SnapshotName string

	// ClusterName is the target cluster the snapshot governs.
	ClusterName string

	// ExpectedVersion is the version the management cluster expects agents to acknowledge.
	ExpectedVersion string

	// LastAckedVersion is the version last acknowledged by the target cluster agent.
	// Empty when no acknowledgement has been received yet.
	LastAckedVersion string

	// IsDrifted is true when the snapshot is in a drift state.
	IsDrifted bool

	// Reason is a human-readable explanation of why the snapshot is drifted.
	// Empty when IsDrifted is false.
	Reason string
}

// ComputeDrift determines whether a PermissionSnapshot is in a drifted state.
// Returns isDrifted bool and reason string.
//
// Four-case logic:
//   - expectedVersion is empty → not drifted (no snapshot generated yet, nothing to ack).
//   - lastAckedVersion is empty → drifted (snapshot exists but never acknowledged).
//   - versions equal → not drifted.
//   - versions differ → drifted with explanation.
func ComputeDrift(expectedVersion, lastAckedVersion string) (bool, string) {
	if expectedVersion == "" {
		return false, "no expected version set"
	}
	if lastAckedVersion == "" {
		return true, "no acknowledgement received from target cluster agent"
	}
	if expectedVersion == lastAckedVersion {
		return false, ""
	}
	return true, fmt.Sprintf("expected %s but last acknowledged %s", expectedVersion, lastAckedVersion)
}

// ReconcileAllDrift computes the drift state for each PermissionSnapshot in the
// input slice. Returns one DriftResult per snapshot, in the same order.
//
// The returned slice is always non-nil. For an empty input it returns an empty
// (non-nil) slice.
func ReconcileAllDrift(snapshots []securityv1alpha1.PermissionSnapshot) []DriftResult {
	results := make([]DriftResult, 0, len(snapshots))
	for _, sn := range snapshots {
		isDrifted, reason := ComputeDrift(sn.Status.ExpectedVersion, sn.Status.LastAckedVersion)
		results = append(results, DriftResult{
			SnapshotName:     sn.Name,
			ClusterName:      sn.Spec.TargetCluster,
			ExpectedVersion:  sn.Status.ExpectedVersion,
			LastAckedVersion: sn.Status.LastAckedVersion,
			IsDrifted:        isDrifted,
			Reason:           reason,
		})
	}
	return results
}
