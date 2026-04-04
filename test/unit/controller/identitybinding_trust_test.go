package controller_test

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
)

// makeValidProvider constructs an IdentityProvider with Valid=True condition.
func makeValidProvider(name string, providerType securityv1alpha1.IdentityProviderType) *securityv1alpha1.IdentityProvider {
	return &securityv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       securityv1alpha1.IdentityProviderSpec{Type: providerType},
		Status: securityv1alpha1.IdentityProviderStatus{
			Conditions: []metav1.Condition{
				{
					Type:   securityv1alpha1.ConditionTypeIdentityProviderValid,
					Status: metav1.ConditionTrue,
					Reason: securityv1alpha1.ReasonIdentityProviderValid,
				},
			},
		},
	}
}

// makeInvalidProvider constructs an IdentityProvider with Valid=False condition.
func makeInvalidProvider(name string, providerType securityv1alpha1.IdentityProviderType) *securityv1alpha1.IdentityProvider {
	return &securityv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       securityv1alpha1.IdentityProviderSpec{Type: providerType},
		Status: securityv1alpha1.IdentityProviderStatus{
			Conditions: []metav1.Condition{
				{
					Type:    securityv1alpha1.ConditionTypeIdentityProviderValid,
					Status:  metav1.ConditionFalse,
					Reason:  securityv1alpha1.ReasonIdentityProviderInvalid,
					Message: "provider validation failed",
				},
			},
		},
	}
}

// TestResolveIdentityProviderTrust_OIDCValid verifies that an OIDC binding resolves
// successfully against a valid OIDC IdentityProvider.
func TestResolveIdentityProviderTrust_OIDCValid(t *testing.T) {
	provider := makeValidProvider("my-oidc", securityv1alpha1.IdentityProviderTypeOIDC)
	result := controller.ResolveIdentityProviderTrust(
		securityv1alpha1.IdentityTypeOIDC, "my-oidc", provider)
	if !result.Resolved {
		t.Errorf("expected Resolved=true; reason=%q message=%q", result.Reason, result.Message)
	}
	if result.Reason != securityv1alpha1.ReasonTrustAnchorResolved {
		t.Errorf("expected reason %q; got %q", securityv1alpha1.ReasonTrustAnchorResolved, result.Reason)
	}
}

// TestResolveIdentityProviderTrust_CertificatePKIValid verifies that a certificate
// binding resolves successfully against a valid PKI IdentityProvider.
func TestResolveIdentityProviderTrust_CertificatePKIValid(t *testing.T) {
	provider := makeValidProvider("my-pki", securityv1alpha1.IdentityProviderTypePKI)
	result := controller.ResolveIdentityProviderTrust(
		securityv1alpha1.IdentityTypeCertificate, "my-pki", provider)
	if !result.Resolved {
		t.Errorf("expected Resolved=true; reason=%q message=%q", result.Reason, result.Message)
	}
}

// TestResolveIdentityProviderTrust_ServiceAccountTokenValid verifies that a
// serviceAccount binding resolves successfully against a valid Token IdentityProvider.
func TestResolveIdentityProviderTrust_ServiceAccountTokenValid(t *testing.T) {
	provider := makeValidProvider("k8s-token", securityv1alpha1.IdentityProviderTypeToken)
	result := controller.ResolveIdentityProviderTrust(
		securityv1alpha1.IdentityTypeServiceAccount, "k8s-token", provider)
	if !result.Resolved {
		t.Errorf("expected Resolved=true; reason=%q message=%q", result.Reason, result.Message)
	}
}

// TestResolveIdentityProviderTrust_ProviderNotFound verifies that a nil provider
// produces TrustAnchorNotFound.
func TestResolveIdentityProviderTrust_ProviderNotFound(t *testing.T) {
	result := controller.ResolveIdentityProviderTrust(
		securityv1alpha1.IdentityTypeOIDC, "missing-provider", nil)
	if result.Resolved {
		t.Error("expected Resolved=false when provider is nil")
	}
	if result.Reason != securityv1alpha1.ReasonTrustAnchorNotFound {
		t.Errorf("expected reason %q; got %q", securityv1alpha1.ReasonTrustAnchorNotFound, result.Reason)
	}
}

// TestResolveIdentityProviderTrust_TypeMismatch verifies that an OIDC binding
// against a PKI IdentityProvider produces TrustAnchorTypeMismatch.
func TestResolveIdentityProviderTrust_TypeMismatch(t *testing.T) {
	provider := makeValidProvider("my-pki", securityv1alpha1.IdentityProviderTypePKI)
	result := controller.ResolveIdentityProviderTrust(
		securityv1alpha1.IdentityTypeOIDC, "my-pki", provider)
	if result.Resolved {
		t.Error("expected Resolved=false for type mismatch (oidc binding vs pki provider)")
	}
	if result.Reason != securityv1alpha1.ReasonTrustAnchorTypeMismatch {
		t.Errorf("expected reason %q; got %q", securityv1alpha1.ReasonTrustAnchorTypeMismatch, result.Reason)
	}
}

// TestResolveIdentityProviderTrust_CertificateAgainstOIDC verifies that a certificate
// binding against an OIDC IdentityProvider produces TrustAnchorTypeMismatch.
func TestResolveIdentityProviderTrust_CertificateAgainstOIDC(t *testing.T) {
	provider := makeValidProvider("my-oidc", securityv1alpha1.IdentityProviderTypeOIDC)
	result := controller.ResolveIdentityProviderTrust(
		securityv1alpha1.IdentityTypeCertificate, "my-oidc", provider)
	if result.Resolved {
		t.Error("expected Resolved=false for type mismatch (certificate binding vs oidc provider)")
	}
	if result.Reason != securityv1alpha1.ReasonTrustAnchorTypeMismatch {
		t.Errorf("expected reason %q; got %q", securityv1alpha1.ReasonTrustAnchorTypeMismatch, result.Reason)
	}
}

// TestResolveIdentityProviderTrust_ProviderInvalid verifies that a valid OIDC
// provider with Valid=False condition produces TrustAnchorInvalid.
func TestResolveIdentityProviderTrust_ProviderInvalid(t *testing.T) {
	provider := makeInvalidProvider("my-oidc", securityv1alpha1.IdentityProviderTypeOIDC)
	result := controller.ResolveIdentityProviderTrust(
		securityv1alpha1.IdentityTypeOIDC, "my-oidc", provider)
	if result.Resolved {
		t.Error("expected Resolved=false when provider has Valid=False")
	}
	if result.Reason != securityv1alpha1.ReasonTrustAnchorInvalid {
		t.Errorf("expected reason %q; got %q", securityv1alpha1.ReasonTrustAnchorInvalid, result.Reason)
	}
}

// TestResolveIdentityProviderTrust_ProviderNoValidCondition verifies that a
// provider with no Valid condition produces TrustAnchorInvalid.
func TestResolveIdentityProviderTrust_ProviderNoValidCondition(t *testing.T) {
	provider := &securityv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "no-cond"},
		Spec:       securityv1alpha1.IdentityProviderSpec{Type: securityv1alpha1.IdentityProviderTypeOIDC},
		Status:     securityv1alpha1.IdentityProviderStatus{}, // no conditions
	}
	result := controller.ResolveIdentityProviderTrust(
		securityv1alpha1.IdentityTypeOIDC, "no-cond", provider)
	if result.Resolved {
		t.Error("expected Resolved=false when provider has no Valid condition")
	}
	if result.Reason != securityv1alpha1.ReasonTrustAnchorInvalid {
		t.Errorf("expected reason %q; got %q", securityv1alpha1.ReasonTrustAnchorInvalid, result.Reason)
	}
}
