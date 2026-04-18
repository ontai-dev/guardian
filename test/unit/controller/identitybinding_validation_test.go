package controller_test

import (
	"testing"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
)

// validOIDCSpec returns a valid OIDC IdentityBindingSpec with mTLS trust.
func validOIDCSpec() securityv1alpha1.IdentityBindingSpec {
	return securityv1alpha1.IdentityBindingSpec{
		IdentityType:  securityv1alpha1.IdentityTypeOIDC,
		PrincipalName: "acme-oidc-user",
		TrustMethod:   securityv1alpha1.TrustMethodMTLS,
		OIDCConfig: &securityv1alpha1.OIDCConfig{
			Issuer:   "https://accounts.example.com",
			ClientID: "ont-client",
		},
	}
}

// TestValidateIdentityBindingSpec_ValidOIDC verifies that a valid OIDC binding
// with mTLS trust passes all checks.
func TestValidateIdentityBindingSpec_ValidOIDC(t *testing.T) {
	result := controller.ValidateIdentityBindingSpec(validOIDCSpec())

	if !result.Valid {
		t.Errorf("expected Valid=true for valid OIDC binding; reasons: %v", result.Reasons)
	}
}

// TestValidateIdentityBindingSpec_ValidServiceAccount verifies that a valid
// ServiceAccount binding passes all checks.
func TestValidateIdentityBindingSpec_ValidServiceAccount(t *testing.T) {
	spec := securityv1alpha1.IdentityBindingSpec{
		IdentityType:  securityv1alpha1.IdentityTypeServiceAccount,
		PrincipalName: "conductor-sa",
		TrustMethod:   securityv1alpha1.TrustMethodMTLS,
		ServiceAccountConfig: &securityv1alpha1.ServiceAccountConfig{
			Name:      "conductor",
			Namespace: "ont-system",
		},
	}

	result := controller.ValidateIdentityBindingSpec(spec)

	if !result.Valid {
		t.Errorf("expected Valid=true for valid ServiceAccount binding; reasons: %v", result.Reasons)
	}
}

// TestValidateIdentityBindingSpec_ValidCertificate verifies that a valid certificate
// binding passes all checks.
func TestValidateIdentityBindingSpec_ValidCertificate(t *testing.T) {
	spec := securityv1alpha1.IdentityBindingSpec{
		IdentityType:  securityv1alpha1.IdentityTypeCertificate,
		PrincipalName: "ont-cert-user",
		TrustMethod:   securityv1alpha1.TrustMethodMTLS,
		CertificateConfig: &securityv1alpha1.CertificateConfig{
			CommonName:   "ont-cert-user",
			Organization: "ONT Platform",
		},
	}

	result := controller.ValidateIdentityBindingSpec(spec)

	if !result.Valid {
		t.Errorf("expected Valid=true for valid Certificate binding; reasons: %v", result.Reasons)
	}
}

// TestValidateIdentityBindingSpec_TokenTTL_AtLimit verifies that
// TokenMaxTTLSeconds=900 is exactly at the limit and is valid.
func TestValidateIdentityBindingSpec_TokenTTL_AtLimit(t *testing.T) {
	spec := securityv1alpha1.IdentityBindingSpec{
		IdentityType:       securityv1alpha1.IdentityTypeOIDC,
		PrincipalName:      "oidc-token-user",
		TrustMethod:        securityv1alpha1.TrustMethodToken,
		TokenMaxTTLSeconds: 900, // exactly at limit — must be valid
		OIDCConfig: &securityv1alpha1.OIDCConfig{
			Issuer:   "https://accounts.example.com",
			ClientID: "ont-client",
		},
	}

	result := controller.ValidateIdentityBindingSpec(spec)

	if !result.Valid {
		t.Errorf("expected Valid=true for TokenMaxTTLSeconds=900 (at limit); reasons: %v", result.Reasons)
	}
}

// TestValidateIdentityBindingSpec_TokenTTL_Exceeded verifies that
// TokenMaxTTLSeconds=901 exceeds the limit and fails with ReasonTokenTTLExceeded.
func TestValidateIdentityBindingSpec_TokenTTL_Exceeded(t *testing.T) {
	spec := securityv1alpha1.IdentityBindingSpec{
		IdentityType:       securityv1alpha1.IdentityTypeOIDC,
		PrincipalName:      "oidc-token-user",
		TrustMethod:        securityv1alpha1.TrustMethodToken,
		TokenMaxTTLSeconds: 901, // one second over the hard limit
		OIDCConfig: &securityv1alpha1.OIDCConfig{
			Issuer:   "https://accounts.example.com",
			ClientID: "ont-client",
		},
	}

	result := controller.ValidateIdentityBindingSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for TokenMaxTTLSeconds=901 (exceeds limit)")
	}
	if !containsAnyReason(result.Reasons, securityv1alpha1.ReasonTokenTTLExceeded) {
		t.Errorf("expected reason containing %q; got: %v", securityv1alpha1.ReasonTokenTTLExceeded, result.Reasons)
	}
}

// TestValidateIdentityBindingSpec_TokenTTL_Zero verifies that
// TokenMaxTTLSeconds=0 fails when trustMethod=token.
func TestValidateIdentityBindingSpec_TokenTTL_Zero(t *testing.T) {
	spec := securityv1alpha1.IdentityBindingSpec{
		IdentityType:       securityv1alpha1.IdentityTypeOIDC,
		PrincipalName:      "oidc-token-user",
		TrustMethod:        securityv1alpha1.TrustMethodToken,
		TokenMaxTTLSeconds: 0,
		OIDCConfig: &securityv1alpha1.OIDCConfig{
			Issuer:   "https://accounts.example.com",
			ClientID: "ont-client",
		},
	}

	result := controller.ValidateIdentityBindingSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for TokenMaxTTLSeconds=0 with trustMethod=token")
	}
}

// TestValidateIdentityBindingSpec_TokenPlusCertificate verifies that the combination
// of TrustMethod=token and IdentityType=certificate fails with TrustMethodMismatch.
func TestValidateIdentityBindingSpec_TokenPlusCertificate(t *testing.T) {
	spec := securityv1alpha1.IdentityBindingSpec{
		IdentityType:       securityv1alpha1.IdentityTypeCertificate,
		PrincipalName:      "cert-user",
		TrustMethod:        securityv1alpha1.TrustMethodToken,
		TokenMaxTTLSeconds: 300,
		CertificateConfig: &securityv1alpha1.CertificateConfig{
			CommonName: "cert-user",
		},
	}

	result := controller.ValidateIdentityBindingSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for token trust + certificate identity combination")
	}
	if !containsAnyReason(result.Reasons, securityv1alpha1.ReasonTrustMethodMismatch) {
		t.Errorf("expected reason containing %q; got: %v", securityv1alpha1.ReasonTrustMethodMismatch, result.Reasons)
	}
}

// TestValidateIdentityBindingSpec_MissingOIDCConfig verifies that an OIDC binding
// without OIDCConfig fails.
func TestValidateIdentityBindingSpec_MissingOIDCConfig(t *testing.T) {
	spec := securityv1alpha1.IdentityBindingSpec{
		IdentityType:  securityv1alpha1.IdentityTypeOIDC,
		PrincipalName: "oidc-user",
		TrustMethod:   securityv1alpha1.TrustMethodMTLS,
		OIDCConfig:    nil, // missing
	}

	result := controller.ValidateIdentityBindingSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for OIDC binding with nil OIDCConfig")
	}
	if !containsAnyReason(result.Reasons, "oidcConfig") {
		t.Errorf("expected reason mentioning oidcConfig; got: %v", result.Reasons)
	}
}

// TestValidateIdentityBindingSpec_EmptyOIDCIssuer verifies that an OIDC binding
// with an empty Issuer fails.
func TestValidateIdentityBindingSpec_EmptyOIDCIssuer(t *testing.T) {
	spec := validOIDCSpec()
	spec.OIDCConfig.Issuer = ""

	result := controller.ValidateIdentityBindingSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for empty OIDCConfig.Issuer")
	}
	if !containsAnyReason(result.Reasons, "issuer") {
		t.Errorf("expected reason mentioning issuer; got: %v", result.Reasons)
	}
}

// TestValidateIdentityBindingSpec_MissingServiceAccountConfig verifies that a
// ServiceAccount binding without ServiceAccountConfig fails.
func TestValidateIdentityBindingSpec_MissingServiceAccountConfig(t *testing.T) {
	spec := securityv1alpha1.IdentityBindingSpec{
		IdentityType:         securityv1alpha1.IdentityTypeServiceAccount,
		PrincipalName:        "sa-user",
		TrustMethod:          securityv1alpha1.TrustMethodMTLS,
		ServiceAccountConfig: nil, // missing
	}

	result := controller.ValidateIdentityBindingSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for ServiceAccount binding with nil ServiceAccountConfig")
	}
	if !containsAnyReason(result.Reasons, "serviceAccountConfig") {
		t.Errorf("expected reason mentioning serviceAccountConfig; got: %v", result.Reasons)
	}
}

// TestValidateIdentityBindingSpec_EmptyPrincipalName verifies that an empty
// PrincipalName fails.
func TestValidateIdentityBindingSpec_EmptyPrincipalName(t *testing.T) {
	spec := validOIDCSpec()
	spec.PrincipalName = ""

	result := controller.ValidateIdentityBindingSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for empty PrincipalName")
	}
	if !containsAnyReason(result.Reasons, "principalName") {
		t.Errorf("expected reason mentioning principalName; got: %v", result.Reasons)
	}
}

// TestValidateIdentityBindingSpec_InvalidIdentityType verifies that an unrecognized
// IdentityType fails.
func TestValidateIdentityBindingSpec_InvalidIdentityType(t *testing.T) {
	spec := validOIDCSpec()
	spec.IdentityType = "kerberosTicket"

	result := controller.ValidateIdentityBindingSpec(spec)

	if result.Valid {
		t.Error("expected Valid=false for invalid IdentityType")
	}
	if !containsAnyReason(result.Reasons, "kerberosTicket") {
		t.Errorf("expected reason containing the invalid identity type; got: %v", result.Reasons)
	}
}
