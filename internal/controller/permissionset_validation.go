package controller

import (
	"fmt"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

// validVerbs is the set of permitted verb values in a PermissionRule.
// guardian-schema.md §7.
var validVerbs = map[string]struct{}{
	"get":              {},
	"list":             {},
	"watch":            {},
	"create":           {},
	"update":           {},
	"patch":            {},
	"delete":           {},
	"deletecollection": {},
}

// PermissionSetValidationResult is the output of ValidatePermissionSetSpec.
// All checks run regardless of earlier failures — the full set of problems is
// collected before returning.
type PermissionSetValidationResult struct {
	// Valid is true if and only if all checks passed.
	Valid bool

	// Reasons contains one human-readable message per failed check.
	// Empty when Valid is true.
	Reasons []string
}

// ValidatePermissionSetSpec validates the structural integrity of a PermissionSetSpec.
//
// All checks run regardless of earlier failures (all-failures collection model).
// This function is pure: no Kubernetes API calls, no side effects.
//
// Checks:
//   - Permissions slice must not be empty.
//   - Each PermissionRule: Resources must not be empty.
//   - Each PermissionRule: Verbs must not be empty.
//   - Each PermissionRule: each verb must be one of the declared valid values.
func ValidatePermissionSetSpec(spec securityv1alpha1.PermissionSetSpec) PermissionSetValidationResult {
	result := PermissionSetValidationResult{
		Valid:   true,
		Reasons: []string{},
	}

	fail := func(msg string) {
		result.Valid = false
		result.Reasons = append(result.Reasons, msg)
	}

	// Check 1 — Permissions slice must not be empty.
	if len(spec.Permissions) == 0 {
		fail("permissions must not be empty; at least one PermissionRule is required")
	}

	// Check 2–4 — Per-rule checks (run even if Check 1 failed, but there are no rules
	// to iterate if empty, so the loop body never executes in that case).
	for i, rule := range spec.Permissions {
		// Check 2 — Resources must not be empty.
		if len(rule.Resources) == 0 {
			fail(fmt.Sprintf("permissions[%d].resources must not be empty", i))
		}

		// Check 3 — Verbs must not be empty.
		if len(rule.Verbs) == 0 {
			fail(fmt.Sprintf("permissions[%d].verbs must not be empty", i))
		}

		// Check 4 — Each verb must be a valid value.
		for _, verb := range rule.Verbs {
			if _, ok := validVerbs[verb]; !ok {
				fail(fmt.Sprintf("permissions[%d].verbs contains invalid value %q; "+
					"valid values: get, list, watch, create, update, patch, delete, deletecollection", i, verb))
			}
		}
	}

	return result
}
