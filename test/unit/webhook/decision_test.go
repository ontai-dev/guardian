// Package webhook_test contains unit tests for the EvaluateAdmission pure function.
//
// These tests verify all decision branches in decision.go: kind filtering,
// annotation enforcement, and the structural presence of the TODO(session-8)
// bootstrap window stub.
package webhook_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ontai-dev/guardian/internal/webhook"
)

// Test 1 — Non-intercepted kind: always allowed regardless of annotations.
func TestEvaluateAdmission_NonInterceptedKind_Allowed(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:        "Deployment",
		Operation:   webhook.OperationCreate,
		Annotations: nil,
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for non-intercepted kind; got reason %q", decision.Reason)
	}
	if decision.Reason != "" {
		t.Errorf("expected empty reason for allowed decision; got %q", decision.Reason)
	}
}

// Test 2 — Role CREATE without annotation: denied.
func TestEvaluateAdmission_Role_NoAnnotation_Denied(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:        "Role",
		Operation:   webhook.OperationCreate,
		Annotations: nil,
	})
	if decision.Allowed {
		t.Error("expected Allowed=false for Role without annotation")
	}
	if decision.Reason == "" {
		t.Error("expected non-empty reason for denied decision")
	}
}

// Test 3 — ClusterRole CREATE without annotation: denied.
func TestEvaluateAdmission_ClusterRole_NoAnnotation_Denied(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:        "ClusterRole",
		Operation:   webhook.OperationCreate,
		Annotations: map[string]string{},
	})
	if decision.Allowed {
		t.Error("expected Allowed=false for ClusterRole without annotation")
	}
}

// Test 4 — RoleBinding CREATE without annotation: denied.
func TestEvaluateAdmission_RoleBinding_NoAnnotation_Denied(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:        "RoleBinding",
		Operation:   webhook.OperationCreate,
		Annotations: map[string]string{},
	})
	if decision.Allowed {
		t.Error("expected Allowed=false for RoleBinding without annotation")
	}
}

// Test 5 — ClusterRoleBinding CREATE without annotation: denied.
func TestEvaluateAdmission_ClusterRoleBinding_NoAnnotation_Denied(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:        "ClusterRoleBinding",
		Operation:   webhook.OperationCreate,
		Annotations: map[string]string{},
	})
	if decision.Allowed {
		t.Error("expected Allowed=false for ClusterRoleBinding without annotation")
	}
}

// Test 6 — ServiceAccount CREATE without annotation: denied.
func TestEvaluateAdmission_ServiceAccount_NoAnnotation_Denied(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:        "ServiceAccount",
		Operation:   webhook.OperationCreate,
		Annotations: nil,
	})
	if decision.Allowed {
		t.Error("expected Allowed=false for ServiceAccount without annotation")
	}
}

// Test 7 — Role with correct annotation: allowed.
func TestEvaluateAdmission_Role_CorrectAnnotation_Allowed(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:      "Role",
		Operation: webhook.OperationCreate,
		Annotations: map[string]string{
			webhook.AnnotationRBACOwner: webhook.AnnotationRBACOwnerValue,
		},
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for Role with correct annotation; got reason %q", decision.Reason)
	}
}

// Test 8 — Role with wrong annotation value: denied.
// Any value other than "guardian" is rejected.
func TestEvaluateAdmission_Role_WrongAnnotationValue_Denied(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:      "Role",
		Operation: webhook.OperationCreate,
		Annotations: map[string]string{
			webhook.AnnotationRBACOwner: "some-other-controller",
		},
	})
	if decision.Allowed {
		t.Error("expected Allowed=false for Role with wrong annotation value")
	}
}

// Test 9 — Role UPDATE without annotation: denied.
// Update operations are intercepted with the same policy as creates.
func TestEvaluateAdmission_Role_Update_NoAnnotation_Denied(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:        "Role",
		Operation:   webhook.OperationUpdate,
		Annotations: nil,
	})
	if decision.Allowed {
		t.Error("expected Allowed=false for Role UPDATE without annotation")
	}
}

// Test 10 — Reason message contains CS-INV-001 reference when denied.
// Denial reasons must reference the invariant for operator observability.
func TestEvaluateAdmission_DeniedReason_ContainsCSINV001(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:        "Role",
		Operation:   webhook.OperationCreate,
		Annotations: nil,
	})
	if decision.Allowed {
		t.Fatal("expected denied decision")
	}
	if !strings.Contains(decision.Reason, "CS-INV-001") {
		t.Errorf("expected reason to contain CS-INV-001; got %q", decision.Reason)
	}
}

// Test 11 — Reason is empty when allowed.
func TestEvaluateAdmission_AllowedReason_IsEmpty(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:      "Role",
		Operation: webhook.OperationCreate,
		Annotations: map[string]string{
			webhook.AnnotationRBACOwner: webhook.AnnotationRBACOwnerValue,
		},
	})
	if !decision.Allowed {
		t.Fatal("expected allowed decision")
	}
	if decision.Reason != "" {
		t.Errorf("expected empty reason for allowed decision; got %q", decision.Reason)
	}
}

// Test 12 — ConfigMap kind (non-RBAC): allowed regardless of annotations.
// The webhook does not intercept core API resources other than ServiceAccount.
func TestEvaluateAdmission_ConfigMap_Allowed(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:        "ConfigMap",
		Operation:   webhook.OperationCreate,
		Annotations: nil,
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for ConfigMap; got reason %q", decision.Reason)
	}
}

// Test 13 — Structural: TODO(session-8) bootstrap window stub is present in decision.go.
// This ensures the bootstrap window implementation point is not accidentally removed
// before Session 8 wires the actual window check. CS-INV-004.
func TestDecisionGo_BootstrapWindowStub_Present(t *testing.T) {
	src, err := os.ReadFile("../../../internal/webhook/decision.go")
	if err != nil {
		t.Fatalf("failed to read decision.go: %v", err)
	}
	if !strings.Contains(string(src), "TODO(session-8)") {
		t.Error("decision.go must contain TODO(session-8) bootstrap window stub; CS-INV-004")
	}
}
