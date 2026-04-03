package controller_test

import (
	"testing"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
)

// TestValidateIdentityProviderSpec_OIDCValid verifies that an OIDC provider
// spec with IssuerURL passes validation.
func TestValidateIdentityProviderSpec_OIDCValid(t *testing.T) {
	spec := securityv1alpha1.IdentityProviderSpec{
		Type:      securityv1alpha1.IdentityProviderTypeOIDC,
		IssuerURL: "https://accounts.example.com",
	}
	result := controller.ValidateIdentityProviderSpec(spec)
	if !result.Valid {
		t.Errorf("expected Valid=true for oidc with IssuerURL; reasons: %v", result.Reasons)
	}
}

// TestValidateIdentityProviderSpec_OIDCMissingIssuerURL verifies that an OIDC
// provider spec without IssuerURL fails validation.
func TestValidateIdentityProviderSpec_OIDCMissingIssuerURL(t *testing.T) {
	spec := securityv1alpha1.IdentityProviderSpec{
		Type: securityv1alpha1.IdentityProviderTypeOIDC,
	}
	result := controller.ValidateIdentityProviderSpec(spec)
	if result.Valid {
		t.Error("expected Valid=false for oidc without IssuerURL")
	}
	if !containsAnyReason(result.Reasons, "issuerURL") {
		t.Errorf("expected reason mentioning issuerURL; got: %v", result.Reasons)
	}
}

// TestValidateIdentityProviderSpec_PKIValid verifies that a PKI provider
// spec with CABundle passes validation.
func TestValidateIdentityProviderSpec_PKIValid(t *testing.T) {
	spec := securityv1alpha1.IdentityProviderSpec{
		Type:      securityv1alpha1.IdentityProviderTypePKI,
		CABundle:  "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
	}
	result := controller.ValidateIdentityProviderSpec(spec)
	if !result.Valid {
		t.Errorf("expected Valid=true for pki with CABundle; reasons: %v", result.Reasons)
	}
}

// TestValidateIdentityProviderSpec_PKIMissingCABundle verifies that a PKI
// provider spec without CABundle fails validation.
func TestValidateIdentityProviderSpec_PKIMissingCABundle(t *testing.T) {
	spec := securityv1alpha1.IdentityProviderSpec{
		Type: securityv1alpha1.IdentityProviderTypePKI,
	}
	result := controller.ValidateIdentityProviderSpec(spec)
	if result.Valid {
		t.Error("expected Valid=false for pki without CABundle")
	}
	if !containsAnyReason(result.Reasons, "caBundle") {
		t.Errorf("expected reason mentioning caBundle; got: %v", result.Reasons)
	}
}

// TestValidateIdentityProviderSpec_TokenValid verifies that a token provider
// spec with TokenSigningKey passes validation.
func TestValidateIdentityProviderSpec_TokenValid(t *testing.T) {
	spec := securityv1alpha1.IdentityProviderSpec{
		Type:            securityv1alpha1.IdentityProviderTypeToken,
		TokenSigningKey: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
	}
	result := controller.ValidateIdentityProviderSpec(spec)
	if !result.Valid {
		t.Errorf("expected Valid=true for token with TokenSigningKey; reasons: %v", result.Reasons)
	}
}

// TestValidateIdentityProviderSpec_TokenMissingSigningKey verifies that a token
// provider spec without TokenSigningKey fails validation.
func TestValidateIdentityProviderSpec_TokenMissingSigningKey(t *testing.T) {
	spec := securityv1alpha1.IdentityProviderSpec{
		Type: securityv1alpha1.IdentityProviderTypeToken,
	}
	result := controller.ValidateIdentityProviderSpec(spec)
	if result.Valid {
		t.Error("expected Valid=false for token without TokenSigningKey")
	}
	if !containsAnyReason(result.Reasons, "tokenSigningKey") {
		t.Errorf("expected reason mentioning tokenSigningKey; got: %v", result.Reasons)
	}
}

// TestValidateIdentityProviderSpec_WrongFieldForType verifies that providing
// the wrong type-specific field (e.g., issuerURL for a pki provider without caBundle)
// fails validation — the required field is still missing.
func TestValidateIdentityProviderSpec_WrongFieldForType(t *testing.T) {
	spec := securityv1alpha1.IdentityProviderSpec{
		Type:      securityv1alpha1.IdentityProviderTypePKI,
		IssuerURL: "https://should-not-matter.example.com", // wrong field for pki
	}
	result := controller.ValidateIdentityProviderSpec(spec)
	if result.Valid {
		t.Error("expected Valid=false for pki without CABundle (issuerURL irrelevant for pki)")
	}
	if !containsAnyReason(result.Reasons, "caBundle") {
		t.Errorf("expected reason mentioning caBundle; got: %v", result.Reasons)
	}
}

// TestValidateIdentityProviderSpec_UnknownType verifies that an unknown type
// value fails validation (defense-in-depth; kubebuilder enum prevents this at admission).
func TestValidateIdentityProviderSpec_UnknownType(t *testing.T) {
	spec := securityv1alpha1.IdentityProviderSpec{
		Type: "ldap",
	}
	result := controller.ValidateIdentityProviderSpec(spec)
	if result.Valid {
		t.Error("expected Valid=false for unknown type")
	}
	if !containsAnyReason(result.Reasons, "type") {
		t.Errorf("expected reason mentioning type; got: %v", result.Reasons)
	}
}

// TestValidateIdentityProviderSpec_OIDCWithOptionalFields verifies that optional
// fields (AllowedAudiences, ValidationRules) do not affect validation outcome.
func TestValidateIdentityProviderSpec_OIDCWithOptionalFields(t *testing.T) {
	spec := securityv1alpha1.IdentityProviderSpec{
		Type:             securityv1alpha1.IdentityProviderTypeOIDC,
		IssuerURL:        "https://accounts.example.com",
		AllowedAudiences: []string{"my-app", "another-app"},
		ValidationRules:  []string{"claims.email_verified == true"},
	}
	result := controller.ValidateIdentityProviderSpec(spec)
	if !result.Valid {
		t.Errorf("expected Valid=true for oidc with optional fields; reasons: %v", result.Reasons)
	}
}
