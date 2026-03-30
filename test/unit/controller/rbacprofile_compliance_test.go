package controller_test

import (
	"testing"

	securityv1alpha1 "github.com/ontai-dev/ont-security/api/v1alpha1"
	"github.com/ontai-dev/ont-security/internal/controller"
)

// strictPolicy returns a base RBACPolicySpec with strict enforcement.
func strictPolicy(allowedClusters []string) securityv1alpha1.RBACPolicySpec {
	return securityv1alpha1.RBACPolicySpec{
		SubjectScope:            securityv1alpha1.SubjectScopeTenant,
		EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
		AllowedClusters:         allowedClusters,
		MaximumPermissionSetRef: "cluster-admin",
	}
}

// auditPolicy returns a base RBACPolicySpec with audit enforcement.
func auditPolicy(allowedClusters []string) securityv1alpha1.RBACPolicySpec {
	return securityv1alpha1.RBACPolicySpec{
		SubjectScope:            securityv1alpha1.SubjectScopeTenant,
		EnforcementMode:         securityv1alpha1.EnforcementModeAudit,
		AllowedClusters:         allowedClusters,
		MaximumPermissionSetRef: "cluster-admin",
	}
}

// tenantProfile returns a profile spec for a tenant principal targeting the given clusters.
func tenantProfile(principal string, clusters []string) securityv1alpha1.RBACProfileSpec {
	return securityv1alpha1.RBACProfileSpec{
		PrincipalRef:   principal,
		RBACPolicyRef:  "some-policy",
		TargetClusters: clusters,
		PermissionDeclarations: []securityv1alpha1.PermissionDeclaration{
			{PermissionSetRef: "cluster-admin", Scope: securityv1alpha1.PermissionScopeCluster},
		},
	}
}

// TestComplianceCheck_ClusterInAllowedList_Strict verifies that a profile targeting
// a cluster that is in the policy AllowedClusters (strict mode) is compliant.
func TestComplianceCheck_ClusterInAllowedList_Strict(t *testing.T) {
	policy := strictPolicy([]string{"ccs-allowed"})
	profile := tenantProfile("acme-admin", []string{"ccs-allowed"})

	result := controller.CheckProfilePolicyCompliance(profile, policy)

	if !result.Compliant {
		t.Errorf("expected Compliant=true; violations: %v", result.Violations)
	}
}

// TestComplianceCheck_ClusterNotInAllowedList_Strict verifies that a profile targeting
// a cluster not in AllowedClusters (strict mode) is not compliant and names the cluster.
func TestComplianceCheck_ClusterNotInAllowedList_Strict(t *testing.T) {
	policy := strictPolicy([]string{"ccs-allowed"})
	profile := tenantProfile("acme-admin", []string{"ccs-forbidden"})

	result := controller.CheckProfilePolicyCompliance(profile, policy)

	if result.Compliant {
		t.Error("expected Compliant=false for cluster not in AllowedClusters (strict)")
	}
	if !containsAnyViolation(result.Violations, "ccs-forbidden") {
		t.Errorf("expected violation naming ccs-forbidden; got: %v", result.Violations)
	}
}

// TestComplianceCheck_EmptyAllowedClusters_Strict verifies that when AllowedClusters
// is empty (management-cluster-only semantics), no restriction is placed on named
// target clusters and all profile clusters are allowed.
//
// Empty AllowedClusters means the policy applies to the management cluster only —
// for compliance purposes this is treated as no restriction on named tenant clusters.
// A policy governing the management plane should not block tenant cluster targeting.
func TestComplianceCheck_EmptyAllowedClusters_Strict(t *testing.T) {
	policy := strictPolicy([]string{}) // empty = no named cluster restriction
	profile := tenantProfile("acme-admin", []string{"ccs-any-cluster"})

	result := controller.CheckProfilePolicyCompliance(profile, policy)

	if !result.Compliant {
		t.Errorf("expected Compliant=true when AllowedClusters is empty (no restriction); violations: %v", result.Violations)
	}
}

// TestComplianceCheck_ClusterNotInAllowedList_Audit verifies that a profile targeting
// a cluster not in AllowedClusters (audit mode) produces Compliant=true with an
// [audit]-prefixed reason string.
func TestComplianceCheck_ClusterNotInAllowedList_Audit(t *testing.T) {
	policy := auditPolicy([]string{"ccs-allowed"})
	profile := tenantProfile("acme-admin", []string{"ccs-not-listed"})

	result := controller.CheckProfilePolicyCompliance(profile, policy)

	if !result.Compliant {
		t.Errorf("expected Compliant=true in audit mode even for unlisted cluster; violations: %v", result.Violations)
	}
	if !containsAnyViolation(result.Violations, "[audit]") {
		t.Errorf("expected an [audit]-prefixed reason; got: %v", result.Violations)
	}
}

// TestComplianceCheck_PlatformPrincipal_TenantPolicy verifies that a principal
// starting with "system:serviceaccount:" governed by a SubjectScopeTenant policy
// is a violation regardless of enforcement mode.
func TestComplianceCheck_PlatformPrincipal_TenantPolicy(t *testing.T) {
	policy := strictPolicy([]string{"ccs-test"})
	policy.SubjectScope = securityv1alpha1.SubjectScopeTenant
	profile := tenantProfile("system:serviceaccount:security-system:ont-security", []string{"ccs-test"})

	result := controller.CheckProfilePolicyCompliance(profile, policy)

	if result.Compliant {
		t.Error("expected Compliant=false for system:serviceaccount: principal with tenant-scope policy")
	}
	if !containsAnyViolation(result.Violations, "system:serviceaccount:") {
		t.Errorf("expected violation naming the principal; got: %v", result.Violations)
	}
}

// TestComplianceCheck_TenantPrincipal_PlatformPolicy verifies that a non-service-account
// principal governed by a SubjectScopePlatform policy is a violation regardless of mode.
func TestComplianceCheck_TenantPrincipal_PlatformPolicy(t *testing.T) {
	policy := strictPolicy([]string{"ccs-test"})
	policy.SubjectScope = securityv1alpha1.SubjectScopePlatform
	profile := tenantProfile("acme-admin", []string{"ccs-test"})

	result := controller.CheckProfilePolicyCompliance(profile, policy)

	if result.Compliant {
		t.Error("expected Compliant=false for tenant principal with platform-scope policy")
	}
	if !containsAnyViolation(result.Violations, "acme-admin") {
		t.Errorf("expected violation naming the principal; got: %v", result.Violations)
	}
}

// TestComplianceCheck_CorrectSubjectScope verifies that the correct SubjectScope
// pairing (tenant principal + tenant policy) produces no SubjectScope violation.
func TestComplianceCheck_CorrectSubjectScope(t *testing.T) {
	policy := strictPolicy([]string{"ccs-test"})
	policy.SubjectScope = securityv1alpha1.SubjectScopeTenant
	profile := tenantProfile("acme-admin", []string{"ccs-test"})

	result := controller.CheckProfilePolicyCompliance(profile, policy)

	if !result.Compliant {
		t.Errorf("expected Compliant=true for correct scope pairing; violations: %v", result.Violations)
	}
}

// TestComplianceCheck_PlatformPrincipal_PlatformPolicy verifies that the platform
// scope pairing (system:serviceaccount + platform policy) is compliant.
func TestComplianceCheck_PlatformPrincipal_PlatformPolicy(t *testing.T) {
	policy := strictPolicy([]string{})
	policy.SubjectScope = securityv1alpha1.SubjectScopePlatform
	profile := tenantProfile("system:serviceaccount:ont-system:ont-runner", []string{})

	result := controller.CheckProfilePolicyCompliance(profile, policy)

	if !result.Compliant {
		t.Errorf("expected Compliant=true for platform scope pairing; violations: %v", result.Violations)
	}
}

// containsAnyViolation is a test helper that returns true if any violation string
// contains the given substring.
func containsAnyViolation(violations []string, substr string) bool {
	for _, v := range violations {
		if len(v) >= len(substr) {
			for i := 0; i <= len(v)-len(substr); i++ {
				if v[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}
