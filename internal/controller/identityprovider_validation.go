package controller

import (
	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

// IdentityProviderValidationResult is the output of ValidateIdentityProviderSpec.
// All checks run regardless of earlier failures — the full set of problems is
// collected before returning.
type IdentityProviderValidationResult struct {
	// Valid is true if and only if all structural checks passed.
	Valid bool

	// Reasons contains one human-readable message per failed check.
	// Empty when Valid is true.
	Reasons []string
}

// ValidateIdentityProviderSpec validates the structural integrity of an IdentityProviderSpec.
//
// All checks run regardless of earlier failures (all-failures collection model).
// This function is pure: no Kubernetes API calls, no HTTP calls, no side effects.
//
// Checks:
//   - Type must be non-empty (enforced by kubebuilder enum at admission, but also
//     checked here for defense in depth).
//   - Type=oidc: IssuerURL must be present.
//   - Type=pki: CABundle must be present.
//   - Type=token: TokenSigningKey must be present.
func ValidateIdentityProviderSpec(spec securityv1alpha1.IdentityProviderSpec) IdentityProviderValidationResult {
	result := IdentityProviderValidationResult{
		Valid:   true,
		Reasons: []string{},
	}

	fail := func(msg string) {
		result.Valid = false
		result.Reasons = append(result.Reasons, msg)
	}

	switch spec.Type {
	case securityv1alpha1.IdentityProviderTypeOIDC:
		if spec.IssuerURL == "" {
			fail("issuerURL is required when type=oidc")
		}
	case securityv1alpha1.IdentityProviderTypePKI:
		if spec.CABundle == "" {
			fail("caBundle is required when type=pki")
		}
	case securityv1alpha1.IdentityProviderTypeToken:
		if spec.TokenSigningKey == "" {
			fail("tokenSigningKey is required when type=token")
		}
	default:
		fail("type must be one of: oidc, pki, token")
	}

	return result
}
