// Package controller contains the reconcilers for the security.ontai.dev API group.
//
// INV-002: ont-security is the one operator with genuine in-process intelligence.
// ValidateRBACPolicySpec performs policy validation entirely in-process, with no
// Kubernetes API calls and no Job submission. This function must never be called
// after a Job has been submitted — that would be an INV-002 violation. The validation
// boundary is this function and the RBACPolicyReconciler that calls it.
package controller

import (
	"fmt"
	"strings"
	"unicode"

	securityv1alpha1 "github.com/ontai-dev/ont-security/api/v1alpha1"
)

// ValidationCheckName is a typed string identifying a specific validation check.
// Each failed check contributes one entry to PolicyValidationResult.FailedChecks.
type ValidationCheckName string

const (
	// CheckSubjectScopeValid verifies that SubjectScope is one of the declared constants.
	CheckSubjectScopeValid ValidationCheckName = "SubjectScopeValid"

	// CheckEnforcementModeValid verifies that EnforcementMode is one of the declared constants.
	CheckEnforcementModeValid ValidationCheckName = "EnforcementModeValid"

	// CheckAllowedClustersFormat verifies that each AllowedClusters entry is a
	// non-empty string with no whitespace characters.
	CheckAllowedClustersFormat ValidationCheckName = "AllowedClustersFormat"

	// CheckMaxPermissionSetRefNotEmpty verifies that MaximumPermissionSetRef is non-empty.
	// NOTE: existence of the referenced PermissionSet CR is not checked here — that
	// check is deferred to when PermissionSet types are defined (Session 4). A TODO
	// is placed in the reconciler at the point where the existence check will be inserted.
	CheckMaxPermissionSetRefNotEmpty ValidationCheckName = "MaxPermissionSetRefNotEmpty"
)

// PolicyValidationResult is the output of ValidateRBACPolicySpec.
// All checks run regardless of earlier failures — the full set of problems is
// collected before returning. Callers receive a complete picture of what is wrong.
type PolicyValidationResult struct {
	// Valid is true if and only if all checks passed.
	Valid bool

	// Reasons contains one human-readable message per failed check.
	// Empty when Valid is true.
	Reasons []string

	// FailedChecks contains the name of each check that failed.
	// Empty when Valid is true.
	FailedChecks []ValidationCheckName
}

// ValidateRBACPolicySpec validates the structural integrity of a RBACPolicySpec.
//
// All four checks run regardless of earlier failures. The returned result
// contains the complete set of failures — not just the first one encountered.
// This is the all-failures collection model.
//
// This function is pure: no Kubernetes API calls, no side effects, no reconciler
// dependencies. It is independently testable without envtest.
//
// INV-002 boundary: this function and RBACPolicyReconciler are the entirety of
// ont-security's in-process validation. No Job is submitted as a result of
// validation. Any future refactor that calls this function after a Job submission
// is an INV-002 violation.
func ValidateRBACPolicySpec(spec securityv1alpha1.RBACPolicySpec) PolicyValidationResult {
	result := PolicyValidationResult{
		Valid:        true,
		Reasons:      []string{},
		FailedChecks: []ValidationCheckName{},
	}

	fail := func(check ValidationCheckName, msg string) {
		result.Valid = false
		result.Reasons = append(result.Reasons, msg)
		result.FailedChecks = append(result.FailedChecks, check)
	}

	// Check 1 — SubjectScope must be one of the declared constants.
	switch spec.SubjectScope {
	case securityv1alpha1.SubjectScopePlatform, securityv1alpha1.SubjectScopeTenant:
		// valid
	default:
		fail(CheckSubjectScopeValid,
			fmt.Sprintf("subjectScope %q is not valid; must be one of: platform, tenant", spec.SubjectScope))
	}

	// Check 2 — EnforcementMode must be one of the declared constants.
	switch spec.EnforcementMode {
	case securityv1alpha1.EnforcementModeStrict, securityv1alpha1.EnforcementModeAudit:
		// valid
	default:
		fail(CheckEnforcementModeValid,
			fmt.Sprintf("enforcementMode %q is not valid; must be one of: strict, audit", spec.EnforcementMode))
	}

	// Check 3 — Each AllowedClusters entry must be non-empty and contain no whitespace.
	for i, cluster := range spec.AllowedClusters {
		if cluster == "" {
			fail(CheckAllowedClustersFormat,
				fmt.Sprintf("allowedClusters[%d] is an empty string; cluster names must be non-empty", i))
			continue
		}
		if strings.IndexFunc(cluster, unicode.IsSpace) >= 0 {
			fail(CheckAllowedClustersFormat,
				fmt.Sprintf("allowedClusters[%d] %q contains whitespace; cluster names must not contain whitespace", i, cluster))
		}
	}

	// Check 4 — MaximumPermissionSetRef must not be empty.
	if spec.MaximumPermissionSetRef == "" {
		fail(CheckMaxPermissionSetRefNotEmpty,
			"maximumPermissionSetRef must not be empty; it must reference a PermissionSet CR by name")
	}

	return result
}
