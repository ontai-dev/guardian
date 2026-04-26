// Package controller_test -- T-VAL-01 Group 4: drift signal and escalation stubs.
//
// DriftSignal creation and the three-state acknowledgement chain (pending → delivered
// → queued → confirmed, Decision I) are not yet implemented. These stubs document
// the required behaviors and will be promoted to live tests when the implementation
// closes.
//
// PackReceipt digest mismatch detection and the existing ComputeDrift /
// ReconcileAllDrift behaviors are already covered by drift_test.go and
// wrapper/test/unit/packinstance_reconciler_test.go.
//
// T-VAL-01, guardian-schema.md §7, Decision H, Decision I.
package controller_test

import "testing"

// TestDriftSignal_CreatedOnMismatch_Stub documents that when PermissionSnapshot
// drift is detected, a DriftSignal CR is written so conductor agents can read it
// and initiate corrective delivery without polling. Decision I.
func TestDriftSignal_CreatedOnMismatch_Stub(t *testing.T) {
	t.Skip("requires DriftSignal type implementation and BACKLOG-DRIFT-SIGNAL closed")
}

// TestDriftSignal_ThreeStateAck_Stub documents the three-state acknowledgement
// chain: pending → delivered → queued → confirmed. Decision I.
func TestDriftSignal_ThreeStateAck_Stub(t *testing.T) {
	t.Skip("requires three-state ack chain implementation and BACKLOG-DRIFT-SIGNAL closed")
}

// TestDriftSignal_EscalationCounter_Stub documents that when the acknowledgement
// counter exceeds a threshold without confirmation, the signal escalates. Decision I.
func TestDriftSignal_EscalationCounter_Stub(t *testing.T) {
	t.Skip("requires escalation counter implementation and BACKLOG-DRIFT-SIGNAL closed")
}

// TestDriftSignal_TerminalDrift_Stub documents the terminal drift condition:
// a snapshot that stays drifted past the escalation threshold triggers a
// management-cluster operator event for human review. Decision H.
func TestDriftSignal_TerminalDrift_Stub(t *testing.T) {
	t.Skip("requires terminal drift condition implementation and BACKLOG-DRIFT-SIGNAL closed")
}
