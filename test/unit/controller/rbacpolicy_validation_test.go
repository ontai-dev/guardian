package controller_test

import (
	"testing"

	securityv1alpha1 "github.com/ontai-dev/ont-security/api/v1alpha1"
	"github.com/ontai-dev/ont-security/internal/controller"
)

// validSpec returns a RBACPolicySpec that passes all four checks. Use this as
// the base for subtests that mutate one field at a time.
func validSpec() securityv1alpha1.RBACPolicySpec {
	return securityv1alpha1.RBACPolicySpec{
		SubjectScope:            securityv1alpha1.SubjectScopePlatform,
		EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
		AllowedClusters:         []string{"ccs-dev", "ccs-test"},
		MaximumPermissionSetRef: "platform-max",
	}
}

// TestValidateRBACPolicySpec_ValidSpec verifies that a fully valid spec passes
// all four checks with no reasons or failed checks.
func TestValidateRBACPolicySpec_ValidSpec(t *testing.T) {
	result := controller.ValidateRBACPolicySpec(validSpec())

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

// TestValidateRBACPolicySpec_TenantScopeIsValid verifies that SubjectScopeTenant
// is accepted in addition to SubjectScopePlatform.
func TestValidateRBACPolicySpec_TenantScopeIsValid(t *testing.T) {
	spec := validSpec()
	spec.SubjectScope = securityv1alpha1.SubjectScopeTenant

	result := controller.ValidateRBACPolicySpec(spec)

	if !result.Valid {
		t.Errorf("expected SubjectScopeTenant to be valid; reasons: %v", result.Reasons)
	}
}

// TestValidateRBACPolicySpec_InvalidSubjectScope verifies that an unrecognized
// SubjectScope value fails CheckSubjectScopeValid.
func TestValidateRBACPolicySpec_InvalidSubjectScope(t *testing.T) {
	spec := validSpec()
	spec.SubjectScope = "superuser"

	result := controller.ValidateRBACPolicySpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for invalid SubjectScope")
	}
	if !containsCheck(result.FailedChecks, controller.CheckSubjectScopeValid) {
		t.Errorf("expected CheckSubjectScopeValid in FailedChecks, got: %v", result.FailedChecks)
	}
}

// TestValidateRBACPolicySpec_AuditModeIsValid verifies that EnforcementModeAudit
// is accepted in addition to EnforcementModeStrict.
func TestValidateRBACPolicySpec_AuditModeIsValid(t *testing.T) {
	spec := validSpec()
	spec.EnforcementMode = securityv1alpha1.EnforcementModeAudit

	result := controller.ValidateRBACPolicySpec(spec)

	if !result.Valid {
		t.Errorf("expected EnforcementModeAudit to be valid; reasons: %v", result.Reasons)
	}
}

// TestValidateRBACPolicySpec_InvalidEnforcementMode verifies that an unrecognized
// EnforcementMode value fails CheckEnforcementModeValid.
func TestValidateRBACPolicySpec_InvalidEnforcementMode(t *testing.T) {
	spec := validSpec()
	spec.EnforcementMode = "permissive"

	result := controller.ValidateRBACPolicySpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for invalid EnforcementMode")
	}
	if !containsCheck(result.FailedChecks, controller.CheckEnforcementModeValid) {
		t.Errorf("expected CheckEnforcementModeValid in FailedChecks, got: %v", result.FailedChecks)
	}
}

// TestValidateRBACPolicySpec_EmptyAllowedClusters verifies that an empty
// AllowedClusters slice is valid (management cluster only semantics).
func TestValidateRBACPolicySpec_EmptyAllowedClusters(t *testing.T) {
	spec := validSpec()
	spec.AllowedClusters = []string{}

	result := controller.ValidateRBACPolicySpec(spec)

	if !result.Valid {
		t.Errorf("expected empty AllowedClusters to be valid; reasons: %v", result.Reasons)
	}
}

// TestValidateRBACPolicySpec_AllowedClustersEmptyEntry verifies that an empty
// string entry in AllowedClusters fails CheckAllowedClustersFormat.
func TestValidateRBACPolicySpec_AllowedClustersEmptyEntry(t *testing.T) {
	spec := validSpec()
	spec.AllowedClusters = []string{"ccs-dev", "", "ccs-test"}

	result := controller.ValidateRBACPolicySpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for empty AllowedClusters entry")
	}
	if !containsCheck(result.FailedChecks, controller.CheckAllowedClustersFormat) {
		t.Errorf("expected CheckAllowedClustersFormat in FailedChecks, got: %v", result.FailedChecks)
	}
}

// TestValidateRBACPolicySpec_AllowedClustersWhitespaceEntry verifies that a
// cluster name containing whitespace fails CheckAllowedClustersFormat.
func TestValidateRBACPolicySpec_AllowedClustersWhitespaceEntry(t *testing.T) {
	spec := validSpec()
	spec.AllowedClusters = []string{"ccs dev"}

	result := controller.ValidateRBACPolicySpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for whitespace in AllowedClusters entry")
	}
	if !containsCheck(result.FailedChecks, controller.CheckAllowedClustersFormat) {
		t.Errorf("expected CheckAllowedClustersFormat in FailedChecks, got: %v", result.FailedChecks)
	}
}

// TestValidateRBACPolicySpec_EmptyMaximumPermissionSetRef verifies that an empty
// MaximumPermissionSetRef fails CheckMaxPermissionSetRefNotEmpty.
func TestValidateRBACPolicySpec_EmptyMaximumPermissionSetRef(t *testing.T) {
	spec := validSpec()
	spec.MaximumPermissionSetRef = ""

	result := controller.ValidateRBACPolicySpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for empty MaximumPermissionSetRef")
	}
	if !containsCheck(result.FailedChecks, controller.CheckMaxPermissionSetRefNotEmpty) {
		t.Errorf("expected CheckMaxPermissionSetRefNotEmpty in FailedChecks, got: %v", result.FailedChecks)
	}
}

// TestValidateRBACPolicySpec_AllFailuresCollected verifies the all-failures
// collection model: when multiple checks fail, all are present in the result.
// This test sets an invalid SubjectScope, invalid EnforcementMode, and an empty
// MaximumPermissionSetRef simultaneously.
func TestValidateRBACPolicySpec_AllFailuresCollected(t *testing.T) {
	spec := securityv1alpha1.RBACPolicySpec{
		SubjectScope:            "bad-scope",
		EnforcementMode:         "bad-mode",
		AllowedClusters:         []string{},
		MaximumPermissionSetRef: "",
	}

	result := controller.ValidateRBACPolicySpec(spec)

	if result.Valid {
		t.Error("expected Valid=false when multiple checks fail")
	}

	expected := []controller.ValidationCheckName{
		controller.CheckSubjectScopeValid,
		controller.CheckEnforcementModeValid,
		controller.CheckMaxPermissionSetRefNotEmpty,
	}
	for _, check := range expected {
		if !containsCheck(result.FailedChecks, check) {
			t.Errorf("expected check %q in FailedChecks, got: %v", check, result.FailedChecks)
		}
	}
	if len(result.Reasons) != len(expected) {
		t.Errorf("expected %d reasons, got %d: %v", len(expected), len(result.Reasons), result.Reasons)
	}
}

// TestValidateRBACPolicySpec_ReasonsMatchFailedChecks verifies that the length
// of Reasons always equals the length of FailedChecks. One reason per check.
func TestValidateRBACPolicySpec_ReasonsMatchFailedChecks(t *testing.T) {
	spec := securityv1alpha1.RBACPolicySpec{
		SubjectScope:            "x",
		EnforcementMode:         "y",
		AllowedClusters:         []string{"", "bad name"},
		MaximumPermissionSetRef: "",
	}

	result := controller.ValidateRBACPolicySpec(spec)

	if len(result.Reasons) != len(result.FailedChecks) {
		t.Errorf("Reasons length %d != FailedChecks length %d",
			len(result.Reasons), len(result.FailedChecks))
	}
}

// TestValidateRBACPolicySpec_ValidResultHasEmptySlices verifies that a passing
// result initializes Reasons and FailedChecks as empty slices (not nil), so
// callers can safely range over them.
func TestValidateRBACPolicySpec_ValidResultHasEmptySlices(t *testing.T) {
	result := controller.ValidateRBACPolicySpec(validSpec())

	if result.Reasons == nil {
		t.Error("expected Reasons to be non-nil empty slice, got nil")
	}
	if result.FailedChecks == nil {
		t.Error("expected FailedChecks to be non-nil empty slice, got nil")
	}
}

// containsCheck is a test helper that returns true if the given check name
// appears in the provided slice.
func containsCheck(checks []controller.ValidationCheckName, target controller.ValidationCheckName) bool {
	for _, c := range checks {
		if c == target {
			return true
		}
	}
	return false
}
