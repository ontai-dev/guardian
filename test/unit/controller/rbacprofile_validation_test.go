package controller_test

import (
	"testing"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
)

// validProfileSpec returns a RBACProfileSpec that passes all six checks.
// Use this as the base for subtests that mutate one field at a time.
func validProfileSpec() securityv1alpha1.RBACProfileSpec {
	return securityv1alpha1.RBACProfileSpec{
		PrincipalRef:   "acme-admin",
		RBACPolicyRef:  "tenant-policy",
		TargetClusters: []string{"ccs-test"},
		PermissionDeclarations: []securityv1alpha1.PermissionDeclaration{
			{
				PermissionSetRef: "cluster-admin",
				Scope:            securityv1alpha1.PermissionScopeCluster,
			},
		},
	}
}

// TestValidateRBACProfileSpec_ValidSpec verifies that a fully valid spec passes
// all six checks with no reasons or failed checks.
func TestValidateRBACProfileSpec_ValidSpec(t *testing.T) {
	result := controller.ValidateRBACProfileSpec(validProfileSpec())

	if !result.Valid {
		t.Errorf("expected Valid=true, got false; reasons: %v", result.Reasons)
	}
	if len(result.Reasons) != 0 {
		t.Errorf("expected no reasons, got: %v", result.Reasons)
	}
	if len(result.FailedChecks) != 0 {
		t.Errorf("expected no failed checks, got: %v", result.FailedChecks)
	}
}

// TestValidateRBACProfileSpec_EmptyPrincipalRef verifies that an empty PrincipalRef fails.
func TestValidateRBACProfileSpec_EmptyPrincipalRef(t *testing.T) {
	spec := validProfileSpec()
	spec.PrincipalRef = ""

	result := controller.ValidateRBACProfileSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for empty PrincipalRef")
	}
	if !containsAnyReason(result.Reasons, "principalRef") {
		t.Errorf("expected reason mentioning principalRef, got: %v", result.Reasons)
	}
}

// TestValidateRBACProfileSpec_EmptyRBACPolicyRef verifies that an empty RBACPolicyRef fails.
func TestValidateRBACProfileSpec_EmptyRBACPolicyRef(t *testing.T) {
	spec := validProfileSpec()
	spec.RBACPolicyRef = ""

	result := controller.ValidateRBACProfileSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for empty RBACPolicyRef")
	}
	if !containsAnyReason(result.Reasons, "rbacPolicyRef") {
		t.Errorf("expected reason mentioning rbacPolicyRef, got: %v", result.Reasons)
	}
}

// TestValidateRBACProfileSpec_EmptyPermissionDeclarations verifies that an empty
// PermissionDeclarations slice fails.
func TestValidateRBACProfileSpec_EmptyPermissionDeclarations(t *testing.T) {
	spec := validProfileSpec()
	spec.PermissionDeclarations = []securityv1alpha1.PermissionDeclaration{}

	result := controller.ValidateRBACProfileSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for empty PermissionDeclarations")
	}
	if !containsAnyReason(result.Reasons, "permissionDeclarations") {
		t.Errorf("expected reason mentioning permissionDeclarations, got: %v", result.Reasons)
	}
}

// TestValidateRBACProfileSpec_EmptyPermissionSetRef verifies that a PermissionDeclaration
// with an empty PermissionSetRef fails.
func TestValidateRBACProfileSpec_EmptyPermissionSetRef(t *testing.T) {
	spec := validProfileSpec()
	spec.PermissionDeclarations = []securityv1alpha1.PermissionDeclaration{
		{PermissionSetRef: "", Scope: securityv1alpha1.PermissionScopeCluster},
	}

	result := controller.ValidateRBACProfileSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for empty PermissionSetRef")
	}
	if !containsAnyReason(result.Reasons, "permissionSetRef") {
		t.Errorf("expected reason mentioning permissionSetRef, got: %v", result.Reasons)
	}
}

// TestValidateRBACProfileSpec_InvalidScope verifies that a PermissionDeclaration with
// an invalid Scope string fails and names the invalid value in the reason.
func TestValidateRBACProfileSpec_InvalidScope(t *testing.T) {
	spec := validProfileSpec()
	spec.PermissionDeclarations = []securityv1alpha1.PermissionDeclaration{
		{PermissionSetRef: "some-set", Scope: "supercluster"},
	}

	result := controller.ValidateRBACProfileSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for invalid Scope")
	}
	if !containsAnyReason(result.Reasons, "supercluster") {
		t.Errorf("expected reason containing the invalid scope value 'supercluster', got: %v", result.Reasons)
	}
}

// TestValidateRBACProfileSpec_NamespacedScopeIsValid verifies that
// PermissionScopeNamespaced is accepted.
func TestValidateRBACProfileSpec_NamespacedScopeIsValid(t *testing.T) {
	spec := validProfileSpec()
	spec.PermissionDeclarations = []securityv1alpha1.PermissionDeclaration{
		{PermissionSetRef: "some-set", Scope: securityv1alpha1.PermissionScopeNamespaced},
	}

	result := controller.ValidateRBACProfileSpec(spec)

	if !result.Valid {
		t.Errorf("expected PermissionScopeNamespaced to be valid; reasons: %v", result.Reasons)
	}
}

// TestValidateRBACProfileSpec_ClusterScopeIsValid verifies that
// PermissionScopeCluster is accepted.
func TestValidateRBACProfileSpec_ClusterScopeIsValid(t *testing.T) {
	spec := validProfileSpec()
	spec.PermissionDeclarations = []securityv1alpha1.PermissionDeclaration{
		{PermissionSetRef: "some-set", Scope: securityv1alpha1.PermissionScopeCluster},
	}

	result := controller.ValidateRBACProfileSpec(spec)

	if !result.Valid {
		t.Errorf("expected PermissionScopeCluster to be valid; reasons: %v", result.Reasons)
	}
}

// TestValidateRBACProfileSpec_EmptyTargetClusters verifies that an empty
// TargetClusters slice fails.
func TestValidateRBACProfileSpec_EmptyTargetClusters(t *testing.T) {
	spec := validProfileSpec()
	spec.TargetClusters = []string{}

	result := controller.ValidateRBACProfileSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for empty TargetClusters")
	}
	if !containsAnyReason(result.Reasons, "targetClusters") {
		t.Errorf("expected reason mentioning targetClusters, got: %v", result.Reasons)
	}
}

// TestValidateRBACProfileSpec_MultipleFailuresCollected verifies the all-failures
// collection model: when multiple checks fail, all are present in the result.
func TestValidateRBACProfileSpec_MultipleFailuresCollected(t *testing.T) {
	spec := securityv1alpha1.RBACProfileSpec{
		PrincipalRef:           "", // fails check 1
		RBACPolicyRef:          "", // fails check 2
		PermissionDeclarations: []securityv1alpha1.PermissionDeclaration{}, // fails check 3
		TargetClusters:         []string{}, // fails check 6
	}

	result := controller.ValidateRBACProfileSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false when multiple checks fail")
	}
	if len(result.FailedChecks) < 4 {
		t.Errorf("expected at least 4 failed checks, got %d: %v", len(result.FailedChecks), result.FailedChecks)
	}
	if len(result.Reasons) != len(result.FailedChecks) {
		t.Errorf("Reasons length %d != FailedChecks length %d",
			len(result.Reasons), len(result.FailedChecks))
	}
}

// containsAnyReason is a test helper that returns true if any reason string
// contains the given substring.
func containsAnyReason(reasons []string, substr string) bool {
	for _, r := range reasons {
		if len(r) >= len(substr) {
			for i := 0; i <= len(r)-len(substr); i++ {
				if r[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}
