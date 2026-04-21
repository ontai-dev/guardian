// Package controller -- AC-2 EPG auto-refresh predicate unit test.
//
// Test 6 from AC-2: verifies that permissionSnapshotStaleFilter passes exactly
// when a PermissionSnapshot transitions from Fresh=True to Fresh=False, and
// suppresses all other update patterns. This predicate is the mechanism by which
// EPGReconciler detects snapshot staleness and triggers immediate recomputation
// without waiting for an annotation-based trigger.
//
// guardian-schema.md §8 EPGReconciler staleness watch.
package controller

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"testing"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	seamconditions "github.com/ontai-dev/seam-core/pkg/conditions"
)

// makeSnapshotWithFresh returns a minimal PermissionSnapshot with the Fresh
// condition set to the given status.
func makeSnapshotWithFresh(name string, fresh bool) *securityv1alpha1.PermissionSnapshot {
	status := metav1.ConditionFalse
	reason := "SnapshotStale"
	if fresh {
		status = metav1.ConditionTrue
		reason = "SnapshotFresh"
	}
	ps := &securityv1alpha1.PermissionSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "security-system"},
	}
	securityv1alpha1.SetCondition(
		&ps.Status.Conditions,
		seamconditions.ConditionTypePermissionSnapshotFresh,
		status,
		reason,
		"test",
		1,
	)
	return ps
}

// TestAC2_EPGStaleFilter_PassesOnFreshToStaleTransition verifies that the
// permissionSnapshotStaleFilter passes update events where Fresh transitions
// from True to False. This is the mechanism that triggers immediate EPG
// recomputation when a PermissionSnapshot becomes stale.
// AC-2 gate: EPG auto-refresh contract. guardian-schema.md §8.
func TestAC2_EPGStaleFilter_PassesOnFreshToStaleTransition(t *testing.T) {
	filter := permissionSnapshotStaleFilter{}
	oldSnap := makeSnapshotWithFresh("ps-ac2", true)  // was Fresh
	newSnap := makeSnapshotWithFresh("ps-ac2", false) // now Stale

	e := event.UpdateEvent{ObjectOld: oldSnap, ObjectNew: newSnap}
	if !filter.Update(e) {
		t.Error("AC-2: stale filter must pass Fresh=True -> Fresh=False transition")
	}
}

// TestAC2_EPGStaleFilter_SuppressesAlreadyStaleUpdate verifies that the filter
// does not pass update events where the snapshot was already stale before the
// update. EPG must not be re-triggered for no-op stale updates.
func TestAC2_EPGStaleFilter_SuppressesAlreadyStaleUpdate(t *testing.T) {
	filter := permissionSnapshotStaleFilter{}
	oldSnap := makeSnapshotWithFresh("ps-ac2-alreadystale", false) // was already Stale
	newSnap := makeSnapshotWithFresh("ps-ac2-alreadystale", false) // still Stale

	e := event.UpdateEvent{ObjectOld: oldSnap, ObjectNew: newSnap}
	if filter.Update(e) {
		t.Error("AC-2: stale filter must suppress already-stale -> stale updates")
	}
}

// TestAC2_EPGStaleFilter_SuppressesFreshToFreshUpdate verifies that the filter
// does not pass update events where the snapshot remains fresh. EPG should not
// be triggered while the snapshot is continuously fresh.
func TestAC2_EPGStaleFilter_SuppressesFreshToFreshUpdate(t *testing.T) {
	filter := permissionSnapshotStaleFilter{}
	oldSnap := makeSnapshotWithFresh("ps-ac2-fresh", true) // was Fresh
	newSnap := makeSnapshotWithFresh("ps-ac2-fresh", true) // still Fresh

	e := event.UpdateEvent{ObjectOld: oldSnap, ObjectNew: newSnap}
	if filter.Update(e) {
		t.Error("AC-2: stale filter must suppress Fresh -> Fresh updates")
	}
}

// TestAC2_EPGStaleFilter_SuppressesStaleToFreshUpdate verifies that the filter
// does not pass update events where the snapshot transitions from Stale back to
// Fresh. EPG recomputation on freshness recovery is handled by the annotation
// trigger, not this predicate.
func TestAC2_EPGStaleFilter_SuppressesStaleToFreshUpdate(t *testing.T) {
	filter := permissionSnapshotStaleFilter{}
	oldSnap := makeSnapshotWithFresh("ps-ac2-recovery", false) // was Stale
	newSnap := makeSnapshotWithFresh("ps-ac2-recovery", true)  // now Fresh

	e := event.UpdateEvent{ObjectOld: oldSnap, ObjectNew: newSnap}
	if filter.Update(e) {
		t.Error("AC-2: stale filter must suppress Stale -> Fresh updates")
	}
}

// TestAC2_EPGStaleFilter_SuppressesFreshCreateEvent verifies that Create events
// for fresh snapshots are suppressed. Only stale snapshots need an immediate recompute.
func TestAC2_EPGStaleFilter_SuppressesFreshCreateEvent(t *testing.T) {
	filter := permissionSnapshotStaleFilter{}
	snap := makeSnapshotWithFresh("ps-ac2-fresh-create", true)

	if filter.Create(event.CreateEvent{Object: snap}) {
		t.Error("AC-2: stale filter must suppress Create events for fresh snapshots")
	}
}

// TestAC2_EPGStaleFilter_PassesStaleCreateEvent verifies that Create events for
// already-stale snapshots are passed. On controller restart the informer cache emits
// synthetic Create events; without this, a snapshot that was Fresh=False before the
// restart would never trigger EPG recomputation.
func TestAC2_EPGStaleFilter_PassesStaleCreateEvent(t *testing.T) {
	filter := permissionSnapshotStaleFilter{}
	snap := makeSnapshotWithFresh("ps-ac2-stale-create", false)

	if !filter.Create(event.CreateEvent{Object: snap}) {
		t.Error("AC-2: stale filter must pass Create events for already-stale snapshots (restart recovery)")
	}
}

// TestAC2_EPGStaleFilter_SuppressesDeleteGenericEvents verifies that Delete and
// Generic events are never passed by the stale filter.
func TestAC2_EPGStaleFilter_SuppressesDeleteGenericEvents(t *testing.T) {
	filter := permissionSnapshotStaleFilter{}
	snap := makeSnapshotWithFresh("ps-ac2-nonevent", true)

	if filter.Delete(event.DeleteEvent{Object: snap}) {
		t.Error("AC-2: stale filter must suppress Delete events")
	}
	if filter.Generic(event.GenericEvent{Object: snap}) {
		t.Error("AC-2: stale filter must suppress Generic events")
	}
}
