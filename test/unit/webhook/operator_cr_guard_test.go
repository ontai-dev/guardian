// Package webhook_test contains unit tests for EvaluateOperatorAuthorship.
//
// These tests verify all decision branches in operator_cr_guard.go:
// kind filtering, operation filtering, bootstrap window bypass,
// operator service account allowance, and human principal denial.
// G-BL-CR-IMMUTABILITY.
package webhook_test

import (
	"testing"

	"github.com/ontai-dev/guardian/internal/webhook"
)

// humanPrincipal is a non-operator username for tests that must be blocked.
const humanPrincipal = "kubernetes-admin"

// operatorSA is a seam operator service account username that must be allowed.
const operatorSA = "system:serviceaccount:seam-system:guardian"

// anotherOperatorSA is a different seam operator service account.
const anotherOperatorSA = "system:serviceaccount:seam-system:wrapper"

// Test 1 -- Human principal blocked on PackInstance update.
func TestOperatorCRGuard_HumanBlocked_PackInstance(t *testing.T) {
	decision := webhook.EvaluateOperatorAuthorship(webhook.OperatorCRGuardRequest{
		Kind:      "PackInstance",
		Operation: webhook.OperationUpdate,
		Username:  humanPrincipal,
	})
	if decision.Allowed {
		t.Error("expected human principal to be denied on PackInstance UPDATE; got allowed")
	}
	if decision.Reason == "" {
		t.Error("expected non-empty denial reason")
	}
}

// Test 2 -- Human principal blocked on RunnerConfig update.
func TestOperatorCRGuard_HumanBlocked_RunnerConfig(t *testing.T) {
	decision := webhook.EvaluateOperatorAuthorship(webhook.OperatorCRGuardRequest{
		Kind:      "RunnerConfig",
		Operation: webhook.OperationUpdate,
		Username:  humanPrincipal,
	})
	if decision.Allowed {
		t.Error("expected human principal to be denied on RunnerConfig UPDATE; got allowed")
	}
}

// Test 3 -- Human principal blocked on PermissionSnapshot update.
func TestOperatorCRGuard_HumanBlocked_PermissionSnapshot(t *testing.T) {
	decision := webhook.EvaluateOperatorAuthorship(webhook.OperatorCRGuardRequest{
		Kind:      "PermissionSnapshot",
		Operation: webhook.OperationUpdate,
		Username:  humanPrincipal,
	})
	if decision.Allowed {
		t.Error("expected human principal to be denied on PermissionSnapshot UPDATE; got allowed")
	}
}

// Test 4 -- Human principal blocked on PackExecution update.
func TestOperatorCRGuard_HumanBlocked_PackExecution(t *testing.T) {
	decision := webhook.EvaluateOperatorAuthorship(webhook.OperatorCRGuardRequest{
		Kind:      "PackExecution",
		Operation: webhook.OperationUpdate,
		Username:  humanPrincipal,
	})
	if decision.Allowed {
		t.Error("expected human principal to be denied on PackExecution UPDATE; got allowed")
	}
}

// Test 5 -- Operator service account allowed on all four protected kinds.
func TestOperatorCRGuard_OperatorSA_AllowedAllFourKinds(t *testing.T) {
	for _, kind := range []string{"PackInstance", "RunnerConfig", "PermissionSnapshot", "PackExecution"} {
		decision := webhook.EvaluateOperatorAuthorship(webhook.OperatorCRGuardRequest{
			Kind:      kind,
			Operation: webhook.OperationUpdate,
			Username:  operatorSA,
		})
		if !decision.Allowed {
			t.Errorf("expected operator SA to be allowed on %s UPDATE; got denied: %s", kind, decision.Reason)
		}
	}
}

// Test 6 -- Different operator SA in seam-system also allowed.
func TestOperatorCRGuard_AnySeamSystemSA_Allowed(t *testing.T) {
	decision := webhook.EvaluateOperatorAuthorship(webhook.OperatorCRGuardRequest{
		Kind:      "RunnerConfig",
		Operation: webhook.OperationUpdate,
		Username:  anotherOperatorSA,
	})
	if !decision.Allowed {
		t.Errorf("expected wrapper SA to be allowed on RunnerConfig UPDATE; got denied: %s", decision.Reason)
	}
}

// Test 7 -- Bootstrap window open allows any principal on all four kinds.
func TestOperatorCRGuard_BootstrapWindowOpen_AllowsAnyPrincipal(t *testing.T) {
	for _, kind := range []string{"PackInstance", "RunnerConfig", "PermissionSnapshot", "PackExecution"} {
		decision := webhook.EvaluateOperatorAuthorship(webhook.OperatorCRGuardRequest{
			Kind:                kind,
			Operation:           webhook.OperationUpdate,
			Username:            humanPrincipal,
			BootstrapWindowOpen: true,
		})
		if !decision.Allowed {
			t.Errorf("expected bootstrap window open to allow %s UPDATE from human; got denied: %s",
				kind, decision.Reason)
		}
	}
}

// Test 8 -- CREATE operation is always allowed, even for human principals.
// Only UPDATE (and PATCH-as-UPDATE) is guarded.
func TestOperatorCRGuard_CreateAllowed_HumanPrincipal(t *testing.T) {
	for _, kind := range []string{"PackInstance", "RunnerConfig", "PermissionSnapshot", "PackExecution"} {
		decision := webhook.EvaluateOperatorAuthorship(webhook.OperatorCRGuardRequest{
			Kind:      kind,
			Operation: webhook.OperationCreate,
			Username:  humanPrincipal,
		})
		if !decision.Allowed {
			t.Errorf("expected CREATE to be allowed for %s; got denied: %s", kind, decision.Reason)
		}
	}
}

// Test 9 -- Non-protected kind is always allowed.
func TestOperatorCRGuard_NonProtectedKind_Allowed(t *testing.T) {
	decision := webhook.EvaluateOperatorAuthorship(webhook.OperatorCRGuardRequest{
		Kind:      "RBACPolicy",
		Operation: webhook.OperationUpdate,
		Username:  humanPrincipal,
	})
	if !decision.Allowed {
		t.Errorf("expected non-protected kind RBACPolicy to be allowed; got denied: %s", decision.Reason)
	}
}

// Test 10 -- SA outside seam-system is blocked (another-system:serviceaccount pattern).
func TestOperatorCRGuard_SAOutsideSeamSystem_Blocked(t *testing.T) {
	decision := webhook.EvaluateOperatorAuthorship(webhook.OperatorCRGuardRequest{
		Kind:      "PackInstance",
		Operation: webhook.OperationUpdate,
		Username:  "system:serviceaccount:default:my-app",
	})
	if decision.Allowed {
		t.Error("expected SA outside seam-system to be denied on PackInstance UPDATE; got allowed")
	}
}
