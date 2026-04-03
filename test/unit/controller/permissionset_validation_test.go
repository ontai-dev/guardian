package controller_test

import (
	"testing"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
)

// validPermissionSetSpec returns a PermissionSetSpec that passes all checks.
func validPermissionSetSpec() securityv1alpha1.PermissionSetSpec {
	return securityv1alpha1.PermissionSetSpec{
		Description: "test set",
		Permissions: []securityv1alpha1.PermissionRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}
}

// TestValidatePermissionSetSpec_ValidSpec verifies that a fully valid spec passes all checks.
func TestValidatePermissionSetSpec_ValidSpec(t *testing.T) {
	result := controller.ValidatePermissionSetSpec(validPermissionSetSpec())

	if !result.Valid {
		t.Errorf("expected Valid=true; reasons: %v", result.Reasons)
	}
	if len(result.Reasons) != 0 {
		t.Errorf("expected no reasons, got: %v", result.Reasons)
	}
}

// TestValidatePermissionSetSpec_EmptyPermissions verifies that an empty
// Permissions slice fails.
func TestValidatePermissionSetSpec_EmptyPermissions(t *testing.T) {
	spec := securityv1alpha1.PermissionSetSpec{
		Description: "empty",
		Permissions: []securityv1alpha1.PermissionRule{},
	}

	result := controller.ValidatePermissionSetSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for empty Permissions")
	}
}

// TestValidatePermissionSetSpec_EmptyResources verifies that a rule with an empty
// Resources slice fails.
func TestValidatePermissionSetSpec_EmptyResources(t *testing.T) {
	spec := validPermissionSetSpec()
	spec.Permissions[0].Resources = []string{}

	result := controller.ValidatePermissionSetSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for empty Resources in rule")
	}
	if !containsAnyReason(result.Reasons, "resources") {
		t.Errorf("expected reason mentioning resources; got: %v", result.Reasons)
	}
}

// TestValidatePermissionSetSpec_EmptyVerbs verifies that a rule with an empty
// Verbs slice fails.
func TestValidatePermissionSetSpec_EmptyVerbs(t *testing.T) {
	spec := validPermissionSetSpec()
	spec.Permissions[0].Verbs = []string{}

	result := controller.ValidatePermissionSetSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for empty Verbs in rule")
	}
	if !containsAnyReason(result.Reasons, "verbs") {
		t.Errorf("expected reason mentioning verbs; got: %v", result.Reasons)
	}
}

// TestValidatePermissionSetSpec_InvalidVerb verifies that an unrecognized verb
// fails and names the invalid value in the reason.
func TestValidatePermissionSetSpec_InvalidVerb(t *testing.T) {
	spec := validPermissionSetSpec()
	spec.Permissions[0].Verbs = []string{"get", "superdelete"}

	result := controller.ValidatePermissionSetSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for invalid verb")
	}
	if !containsAnyReason(result.Reasons, "superdelete") {
		t.Errorf("expected reason naming the invalid verb 'superdelete'; got: %v", result.Reasons)
	}
}

// TestValidatePermissionSetSpec_AllValidVerbs verifies that all eight declared
// valid verbs are individually accepted.
func TestValidatePermissionSetSpec_AllValidVerbs(t *testing.T) {
	validVerbs := []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}
	for _, verb := range validVerbs {
		t.Run(verb, func(t *testing.T) {
			spec := validPermissionSetSpec()
			spec.Permissions[0].Verbs = []string{verb}

			result := controller.ValidatePermissionSetSpec(spec)

			if !result.Valid {
				t.Errorf("expected verb %q to be valid; reasons: %v", verb, result.Reasons)
			}
		})
	}
}

// TestValidatePermissionSetSpec_MultipleFailuresCollected verifies that when
// multiple rules have failures, all are collected.
func TestValidatePermissionSetSpec_MultipleFailuresCollected(t *testing.T) {
	spec := securityv1alpha1.PermissionSetSpec{
		Permissions: []securityv1alpha1.PermissionRule{
			{Resources: []string{}, Verbs: []string{}},        // fails resources + verbs
			{Resources: []string{"pods"}, Verbs: []string{"badverb"}}, // fails verb
		},
	}

	result := controller.ValidatePermissionSetSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false with multiple failures")
	}
	if len(result.Reasons) < 3 {
		t.Errorf("expected at least 3 reasons (empty resources, empty verbs, invalid verb), got %d: %v",
			len(result.Reasons), result.Reasons)
	}
}
