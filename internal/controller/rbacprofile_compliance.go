package controller

import (
	"fmt"
	"strings"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

// ComplianceCheckResult is the output of CheckProfilePolicyCompliance.
// All rules are evaluated and all violations are collected before returning.
type ComplianceCheckResult struct {
	// Compliant is true if all rules pass with no violations.
	// In Audit mode, cluster-scope mismatches produce reason strings but Compliant remains true.
	Compliant bool

	// Violations contains one string per violated rule.
	// Empty when Compliant is true.
	Violations []string
}

// CheckProfilePolicyCompliance checks whether a RBACProfile is compliant with
// its governing RBACPolicy.
//
// This function is pure: it accepts already-fetched objects and returns a result.
// No Kubernetes API calls are made inside this function.
//
// Rules:
//
//  1. Strict mode: every cluster in TargetClusters must appear in AllowedClusters
//     (if AllowedClusters is non-empty). A missing cluster is a violation.
//     Audit mode: cluster mismatches produce an "[audit]" reason but Compliant=true.
//
//  2. SubjectScope on the governing policy must match the principal type:
//     - PrincipalRef starting with "system:serviceaccount:" → SubjectScopePlatform required.
//     - All other principals → SubjectScopeTenant required.
//     Mismatch is a violation regardless of EnforcementMode.
func CheckProfilePolicyCompliance(
	profileSpec securityv1alpha1.RBACProfileSpec,
	policySpec securityv1alpha1.RBACPolicySpec,
) ComplianceCheckResult {
	result := ComplianceCheckResult{
		Compliant:  true,
		Violations: []string{},
	}

	violate := func(msg string) {
		result.Compliant = false
		result.Violations = append(result.Violations, msg)
	}

	// Rule 1 — Cluster scope check.
	// Empty AllowedClusters means management cluster only — for compliance purposes
	// treat as no restriction on named target clusters (any named cluster is allowed).
	// This matches the management-cluster-only semantic: the policy applies to the
	// management plane, and named clusters in the profile are tenant clusters. When
	// AllowedClusters is empty, the policy does not constrain which tenant clusters
	// the profile may target.
	if len(policySpec.AllowedClusters) > 0 {
		allowedSet := make(map[string]struct{}, len(policySpec.AllowedClusters))
		for _, c := range policySpec.AllowedClusters {
			allowedSet[c] = struct{}{}
		}

		for _, cluster := range profileSpec.TargetClusters {
			if _, ok := allowedSet[cluster]; !ok {
				switch policySpec.EnforcementMode {
				case securityv1alpha1.EnforcementModeStrict:
					violate(fmt.Sprintf("cluster %q is not in governing policy AllowedClusters", cluster))
				case securityv1alpha1.EnforcementModeAudit:
					// Audit mode: log mismatch but Compliant remains true.
					result.Violations = append(result.Violations,
						fmt.Sprintf("[audit] cluster %q is not in governing policy AllowedClusters; would be a violation in strict mode", cluster))
				}
			}
		}
	}

	// Rule 2 — SubjectScope must match the principal type.
	// Principals starting with "system:serviceaccount:" are platform service accounts
	// and must be governed by a platform-scope policy.
	// All other principals are tenant principals and must be governed by a tenant-scope policy.
	isPlatformPrincipal := strings.HasPrefix(profileSpec.PrincipalRef, "system:serviceaccount:")
	if isPlatformPrincipal {
		if policySpec.SubjectScope != securityv1alpha1.SubjectScopePlatform {
			violate(fmt.Sprintf(
				"principalRef %q is a platform service account but governing policy has subjectScope=%q; "+
					"platform service accounts must be governed by a policy with subjectScope=platform",
				profileSpec.PrincipalRef, policySpec.SubjectScope))
		}
	} else {
		if policySpec.SubjectScope != securityv1alpha1.SubjectScopeTenant {
			violate(fmt.Sprintf(
				"principalRef %q is a tenant principal but governing policy has subjectScope=%q; "+
					"tenant principals must be governed by a policy with subjectScope=tenant",
				profileSpec.PrincipalRef, policySpec.SubjectScope))
		}
	}

	// For audit mode, the only violations that make the result non-compliant are
	// Rule 2 violations (SubjectScope mismatch is always a hard violation).
	// Rule 1 audit-mode entries are appended to Violations as informational strings
	// but do not flip Compliant to false. Re-evaluate compliance based on hard violations only.
	hasHardViolation := false
	for _, v := range result.Violations {
		if !strings.HasPrefix(v, "[audit]") {
			hasHardViolation = true
			break
		}
	}
	result.Compliant = !hasHardViolation

	return result
}
