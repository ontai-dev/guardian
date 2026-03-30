package controller

import (
	"fmt"

	securityv1alpha1 "github.com/ontai-dev/ont-security/api/v1alpha1"
)

// IdentityBindingValidationResult is the output of ValidateIdentityBindingSpec.
// All checks run regardless of earlier failures (all-failures collection model).
type IdentityBindingValidationResult struct {
	// Valid is true if and only if all checks passed.
	Valid bool

	// Reasons contains one human-readable message per failed check.
	// Empty when Valid is true.
	Reasons []string
}

// tokenMaxTTL is the hard security constraint on token max TTL.
// This value is not configurable. ont-security-schema.md §7.
const tokenMaxTTL = 900

// ValidateIdentityBindingSpec validates the structural integrity of an IdentityBindingSpec.
//
// All checks run regardless of earlier failures (all-failures collection model).
// This function is pure: no Kubernetes API calls, no side effects.
//
// Checks:
//   - PrincipalName must not be empty.
//   - IdentityType must be one of the declared constants.
//   - TrustMethod must be one of the declared constants.
//   - If TrustMethod=token: TokenMaxTTLSeconds must be > 0 and ≤ 900.
//   - If TrustMethod=token and IdentityType=certificate: invalid combination (TrustMethodMismatch).
//   - If IdentityType=oidc: OIDCConfig must not be nil; Issuer must not be empty.
//   - If IdentityType=serviceAccount: ServiceAccountConfig must not be nil; Name and Namespace non-empty.
//   - If IdentityType=certificate: CertificateConfig must not be nil; CommonName non-empty.
func ValidateIdentityBindingSpec(spec securityv1alpha1.IdentityBindingSpec) IdentityBindingValidationResult {
	result := IdentityBindingValidationResult{
		Valid:   true,
		Reasons: []string{},
	}

	fail := func(msg string) {
		result.Valid = false
		result.Reasons = append(result.Reasons, msg)
	}

	// Check 1 — PrincipalName must not be empty.
	if spec.PrincipalName == "" {
		fail("principalName must not be empty")
	}

	// Check 2 — IdentityType must be a declared constant.
	validIdentityType := false
	switch spec.IdentityType {
	case securityv1alpha1.IdentityTypeOIDC,
		securityv1alpha1.IdentityTypeServiceAccount,
		securityv1alpha1.IdentityTypeCertificate:
		validIdentityType = true
	default:
		fail(fmt.Sprintf("identityType %q is not valid; must be one of: oidc, serviceAccount, certificate", spec.IdentityType))
	}

	// Check 3 — TrustMethod must be a declared constant.
	validTrustMethod := false
	switch spec.TrustMethod {
	case securityv1alpha1.TrustMethodMTLS, securityv1alpha1.TrustMethodToken:
		validTrustMethod = true
	default:
		fail(fmt.Sprintf("trustMethod %q is not valid; must be one of: mtls, token", spec.TrustMethod))
	}

	// Check 4 — Token TTL hard constraint.
	// ont-security-schema.md §7: 15-minute maximum. Non-configurable. Non-overridable.
	if validTrustMethod && spec.TrustMethod == securityv1alpha1.TrustMethodToken {
		if spec.TokenMaxTTLSeconds <= 0 {
			fail("tokenMaxTTLSeconds must be greater than 0 when trustMethod=token")
		} else if spec.TokenMaxTTLSeconds > tokenMaxTTL {
			fail(fmt.Sprintf("%s: tokenMaxTTLSeconds %d exceeds the hard limit of %d seconds (15 minutes); "+
				"this is a non-configurable security constraint per ont-security-schema.md §7",
				securityv1alpha1.ReasonTokenTTLExceeded, spec.TokenMaxTTLSeconds, tokenMaxTTL))
		}
	}

	// Check 5 — Token trust with certificate identity is invalid (TrustMethodMismatch).
	// Certificate identity implies mTLS — using token trust with certificate identity
	// is semantically contradictory.
	if validIdentityType && validTrustMethod &&
		spec.TrustMethod == securityv1alpha1.TrustMethodToken &&
		spec.IdentityType == securityv1alpha1.IdentityTypeCertificate {
		fail(fmt.Sprintf("%s: certificate identity implies mTLS trust; token trustMethod is invalid with identityType=certificate",
			securityv1alpha1.ReasonTrustMethodMismatch))
	}

	// Checks 6–8 — Identity-type-specific config checks (only when IdentityType is valid).
	if validIdentityType {
		switch spec.IdentityType {
		case securityv1alpha1.IdentityTypeOIDC:
			// Check 6 — OIDCConfig must not be nil; Issuer must not be empty.
			if spec.OIDCConfig == nil {
				fail("oidcConfig must not be nil when identityType=oidc")
			} else if spec.OIDCConfig.Issuer == "" {
				fail("oidcConfig.issuer must not be empty when identityType=oidc")
			}

		case securityv1alpha1.IdentityTypeServiceAccount:
			// Check 7 — ServiceAccountConfig must not be nil; Name and Namespace non-empty.
			if spec.ServiceAccountConfig == nil {
				fail("serviceAccountConfig must not be nil when identityType=serviceAccount")
			} else {
				if spec.ServiceAccountConfig.Name == "" {
					fail("serviceAccountConfig.name must not be empty when identityType=serviceAccount")
				}
				if spec.ServiceAccountConfig.Namespace == "" {
					fail("serviceAccountConfig.namespace must not be empty when identityType=serviceAccount")
				}
			}

		case securityv1alpha1.IdentityTypeCertificate:
			// Check 8 — CertificateConfig must not be nil; CommonName non-empty.
			if spec.CertificateConfig == nil {
				fail("certificateConfig must not be nil when identityType=certificate")
			} else if spec.CertificateConfig.CommonName == "" {
				fail("certificateConfig.commonName must not be empty when identityType=certificate")
			}
		}
	}

	return result
}
