// Package webhook_test contains unit tests for the EvaluateAdmission pure function
// and the BootstrapWindow type.
//
// These tests verify all decision branches in decision.go: kind filtering,
// annotation enforcement, bootstrap RBAC window behavior (INV-020, CS-INV-004),
// and BootstrapWindow state transitions.
package webhook_test

import (
	"strings"
	"testing"

	"github.com/ontai-dev/guardian/internal/webhook"
)

// --- EvaluateAdmission: non-intercepted kinds ---

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

// --- EvaluateAdmission: annotation enforcement (bootstrap window closed) ---

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

// --- BootstrapWindow state tests ---

// Test 13 — BootstrapWindow starts open immediately after construction. INV-020.
func TestBootstrapWindow_StartsOpen(t *testing.T) {
	w := webhook.NewBootstrapWindow()
	if !w.IsOpen() {
		t.Error("BootstrapWindow must be open on construction; INV-020")
	}
}

// Test 14 — BootstrapWindow.Close permanently closes the window. INV-020.
func TestBootstrapWindow_Close_ClosesWindow(t *testing.T) {
	w := webhook.NewBootstrapWindow()
	w.Close()
	if w.IsOpen() {
		t.Error("BootstrapWindow.IsOpen() must return false after Close(); INV-020")
	}
}

// Test 15 — BootstrapWindow.Close is idempotent. Calling it multiple times must
// not panic and must leave the window closed. INV-020.
func TestBootstrapWindow_Close_Idempotent(t *testing.T) {
	w := webhook.NewBootstrapWindow()
	w.Close()
	w.Close() // must not panic
	if w.IsOpen() {
		t.Error("BootstrapWindow must remain closed after multiple Close() calls; INV-020")
	}
}

// Test 16 — BootstrapWindow cannot be re-opened once closed. There is no
// re-open method; the window is permanently closed by design. INV-020.
func TestBootstrapWindow_OnceClosedStaysClosed(t *testing.T) {
	w := webhook.NewBootstrapWindow()
	w.Close()
	// No re-open path exists. Verify the closed state is stable.
	for range 3 {
		if w.IsOpen() {
			t.Error("BootstrapWindow must not re-open after Close(); INV-020")
		}
	}
}

// --- EvaluateAdmission: bootstrap window open ---

// Test 17 — Bootstrap window open: intercepted RBAC without annotation is allowed.
// During the bootstrap window, the conductor enable phase applies guardian's own
// RBAC before the ownership annotation can be set. INV-020, CS-INV-004.
func TestEvaluateAdmission_BootstrapWindowOpen_Role_NoAnnotation_Allowed(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:                "Role",
		Operation:           webhook.OperationCreate,
		Annotations:         nil,
		BootstrapWindowOpen: true,
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for Role during bootstrap window; got reason %q", decision.Reason)
	}
}

// Test 18 — Bootstrap window open: all intercepted RBAC kinds are allowed without
// annotation. The window opens the path for all five intercepted kinds equally.
// INV-020, CS-INV-004.
func TestEvaluateAdmission_BootstrapWindowOpen_AllInterceptedKinds_Allowed(t *testing.T) {
	kinds := []string{"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "ServiceAccount"}
	for _, kind := range kinds {
		decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
			Kind:                kind,
			Operation:           webhook.OperationCreate,
			BootstrapWindowOpen: true,
		})
		if !decision.Allowed {
			t.Errorf("kind %q: expected Allowed=true during bootstrap window; got reason %q",
				kind, decision.Reason)
		}
	}
}

// Test 19 — Bootstrap window open: non-intercepted kinds remain allowed (unchanged).
// The window does not alter behavior for kinds outside InterceptedKinds.
func TestEvaluateAdmission_BootstrapWindowOpen_NonInterceptedKind_Allowed(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:                "Deployment",
		Operation:           webhook.OperationCreate,
		BootstrapWindowOpen: true,
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for Deployment during bootstrap window; got reason %q",
			decision.Reason)
	}
}

// Test 20 — Bootstrap window closed: intercepted RBAC without annotation is denied.
// This is the normal enforcement path — BootstrapWindowOpen=false is identical to
// omitting the field (zero value). CS-INV-001, INV-020.
func TestEvaluateAdmission_BootstrapWindowClosed_NoAnnotation_Denied(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:                "Role",
		Operation:           webhook.OperationCreate,
		Annotations:         nil,
		BootstrapWindowOpen: false,
	})
	if decision.Allowed {
		t.Error("expected Allowed=false when bootstrap window closed and no annotation; CS-INV-001")
	}
}

// Test 21 — Bootstrap window closed: correct annotation is still allowed.
// Closing the window does not affect the normal ownership-annotated resource path.
func TestEvaluateAdmission_BootstrapWindowClosed_CorrectAnnotation_Allowed(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:      "ClusterRole",
		Operation: webhook.OperationCreate,
		Annotations: map[string]string{
			webhook.AnnotationRBACOwner: webhook.AnnotationRBACOwnerValue,
		},
		BootstrapWindowOpen: false,
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for annotated ClusterRole after window closes; got reason %q",
			decision.Reason)
	}
}
