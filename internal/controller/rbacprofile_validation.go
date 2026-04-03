package controller

import (
	"fmt"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

// ProfileValidationResult is the output of ValidateRBACProfileSpec.
// All checks run regardless of earlier failures — the full set of problems is
// collected before returning.
type ProfileValidationResult struct {
	// Valid is true if and only if all checks passed.
	Valid bool

	// Reasons contains one human-readable message per failed check.
	// Empty when Valid is true.
	Reasons []string

	// FailedChecks contains a short identifier for each failed check.
	// Empty when Valid is true.
	FailedChecks []string
}

// ValidateRBACProfileSpec validates the structural integrity of a RBACProfileSpec.
//
// All six checks run regardless of earlier failures (all-failures collection model).
// This function is pure: no Kubernetes API calls, no side effects.
//
// Checks:
//  1. PrincipalRef must not be empty.
//  2. RBACPolicyRef must not be empty.
//  3. PermissionDeclarations must not be empty.
//  4. Each PermissionDeclaration: PermissionSetRef must not be empty.
//  5. Each PermissionDeclaration: Scope must be a declared PermissionScope constant.
//  6. TargetClusters must not be empty.
func ValidateRBACProfileSpec(spec securityv1alpha1.RBACProfileSpec) ProfileValidationResult {
	result := ProfileValidationResult{
		Valid:        true,
		Reasons:      []string{},
		FailedChecks: []string{},
	}

	fail := func(check, msg string) {
		result.Valid = false
		result.Reasons = append(result.Reasons, msg)
		result.FailedChecks = append(result.FailedChecks, check)
	}

	// Check 1 — PrincipalRef must not be empty.
	if spec.PrincipalRef == "" {
		fail("PrincipalRefNotEmpty", "principalRef must not be empty")
	}

	// Check 2 — RBACPolicyRef must not be empty.
	if spec.RBACPolicyRef == "" {
		fail("RBACPolicyRefNotEmpty", "rbacPolicyRef must not be empty; it must reference a governing RBACPolicy by name")
	}

	// Check 3 — PermissionDeclarations must not be empty.
	if len(spec.PermissionDeclarations) == 0 {
		fail("PermissionDeclarationsNotEmpty", "permissionDeclarations must not be empty; at least one declaration is required")
	}

	// Checks 4–5 — Per-declaration checks.
	for i, decl := range spec.PermissionDeclarations {
		// Check 4 — PermissionSetRef must not be empty.
		if decl.PermissionSetRef == "" {
			fail("PermissionSetRefNotEmpty",
				fmt.Sprintf("permissionDeclarations[%d].permissionSetRef must not be empty", i))
		}

		// Check 5 — Scope must be a declared constant.
		switch decl.Scope {
		case securityv1alpha1.PermissionScopeNamespaced, securityv1alpha1.PermissionScopeCluster:
			// valid
		default:
			fail("ScopeValid",
				fmt.Sprintf("permissionDeclarations[%d].scope %q is not valid; must be one of: namespaced, cluster", i, decl.Scope))
		}
	}

	// Check 6 — TargetClusters must not be empty.
	if len(spec.TargetClusters) == 0 {
		fail("TargetClustersNotEmpty",
			"targetClusters must not be empty; a profile with no target clusters grants access to nothing")
	}

	return result
}
