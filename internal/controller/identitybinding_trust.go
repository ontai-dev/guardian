package controller

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

// TrustResolutionResult is the output of ResolveIdentityProviderTrust.
type TrustResolutionResult struct {
	// Resolved is true when the IdentityProvider was found, type-matched, and is valid.
	Resolved bool

	// Reason is the CamelCase reason code for the condition.
	Reason string

	// Message is a human-readable explanation.
	Message string
}

// requiredProviderType returns the IdentityProvider type expected for the given
// IdentityBinding identity type. Returns ("", false) when no provider type
// constraint applies (currently unused, reserved for future identity types).
func requiredProviderType(idType securityv1alpha1.IdentityType) (securityv1alpha1.IdentityProviderType, bool) {
	switch idType {
	case securityv1alpha1.IdentityTypeOIDC:
		return securityv1alpha1.IdentityProviderTypeOIDC, true
	case securityv1alpha1.IdentityTypeCertificate:
		return securityv1alpha1.IdentityProviderTypePKI, true
	case securityv1alpha1.IdentityTypeServiceAccount:
		return securityv1alpha1.IdentityProviderTypeToken, true
	default:
		return "", false
	}
}

// ResolveIdentityProviderTrust validates that provider is the correct trust anchor
// for a binding with the given identityType.
//
// Parameters:
//   - identityType: the IdentityType from the binding's spec.
//   - providerRef: the IdentityProviderRef name from the binding's spec.
//   - provider: the fetched IdentityProvider, or nil if not found.
//
// This function is pure: no Kubernetes API calls, no side effects. It can be
// unit-tested without a cluster. guardian-schema.md §7 — trust anchor contract.
func ResolveIdentityProviderTrust(
	identityType securityv1alpha1.IdentityType,
	providerRef string,
	provider *securityv1alpha1.IdentityProvider,
) TrustResolutionResult {
	// Not found.
	if provider == nil {
		return TrustResolutionResult{
			Resolved: false,
			Reason:   securityv1alpha1.ReasonTrustAnchorNotFound,
			Message:  fmt.Sprintf("IdentityProvider %q not found in namespace", providerRef),
		}
	}

	// Type mismatch check.
	expectedType, hasConstraint := requiredProviderType(identityType)
	if hasConstraint && provider.Spec.Type != expectedType {
		return TrustResolutionResult{
			Resolved: false,
			Reason:   securityv1alpha1.ReasonTrustAnchorTypeMismatch,
			Message: fmt.Sprintf(
				"IdentityProvider %q has type %q but identityType %q requires provider type %q",
				providerRef, provider.Spec.Type, identityType, expectedType,
			),
		}
	}

	// Valid condition check: provider must have Valid=True.
	validCond := securityv1alpha1.FindCondition(provider.Status.Conditions,
		securityv1alpha1.ConditionTypeIdentityProviderValid)
	if validCond == nil || validCond.Status != metav1.ConditionTrue {
		msg := fmt.Sprintf("IdentityProvider %q does not have Valid=True condition", providerRef)
		if validCond != nil {
			msg = fmt.Sprintf("IdentityProvider %q Valid condition is %s: %s",
				providerRef, validCond.Status, validCond.Message)
		}
		return TrustResolutionResult{
			Resolved: false,
			Reason:   securityv1alpha1.ReasonTrustAnchorInvalid,
			Message:  msg,
		}
	}

	return TrustResolutionResult{
		Resolved: true,
		Reason:   securityv1alpha1.ReasonTrustAnchorResolved,
		Message: fmt.Sprintf("IdentityProvider %q (type %q) is valid and type-matched.",
			providerRef, provider.Spec.Type),
	}
}
