package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IdentityProviderType is the class of external identity source.
//
// +kubebuilder:validation:Enum=oidc;pki;token
type IdentityProviderType string

const (
	// IdentityProviderTypeOIDC is an OpenID Connect identity provider.
	// Requires IssuerURL. Reachability is verified by the reconciler.
	IdentityProviderTypeOIDC IdentityProviderType = "oidc"

	// IdentityProviderTypePKI is a PKI certificate authority identity provider.
	// Requires CABundle.
	IdentityProviderTypePKI IdentityProviderType = "pki"

	// IdentityProviderTypeToken is a token-based identity provider.
	// Requires TokenSigningKey.
	IdentityProviderTypeToken IdentityProviderType = "token"
)

// Condition type constants for IdentityProvider.
const (
	// ConditionTypeIdentityProviderValid indicates whether the IdentityProvider
	// spec is structurally valid and has all type-required fields present.
	ConditionTypeIdentityProviderValid = "Valid"

	// ConditionTypeIdentityProviderReachable indicates whether the upstream identity
	// source is reachable. Applies to OIDC providers only — the reconciler fetches
	// the OIDC discovery document to verify reachability. Not set for PKI or Token.
	ConditionTypeIdentityProviderReachable = "Reachable"
)

// Condition reason constants for IdentityProvider.
const (
	ReasonIdentityProviderValid        = "Valid"
	ReasonIdentityProviderInvalid      = "Invalid"
	ReasonIdentityProviderReachable    = "Reachable"
	ReasonIdentityProviderUnreachable  = "Unreachable"
	ReasonIdentityProviderPending      = "Pending"
)

// IdentityProviderSpec defines the desired state of an IdentityProvider.
type IdentityProviderSpec struct {
	// Type is the identity provider class. Determines which configuration fields
	// are required: oidc requires IssuerURL, pki requires CABundle, token requires
	// TokenSigningKey. guardian-schema.md §7.
	// +kubebuilder:validation:Enum=oidc;pki;token
	Type IdentityProviderType `json:"type"`

	// IssuerURL is the OIDC provider URL. Required when Type=oidc.
	// The reconciler fetches {IssuerURL}/.well-known/openid-configuration to verify
	// reachability and set the Reachable condition.
	// +optional
	IssuerURL string `json:"issuerURL,omitempty"`

	// CABundle is the PEM-encoded CA certificate bundle for PKI trust.
	// Required when Type=pki.
	// +optional
	CABundle string `json:"caBundle,omitempty"`

	// TokenSigningKey is the PEM-encoded public key used to verify token signatures.
	// Required when Type=token.
	// +optional
	TokenSigningKey string `json:"tokenSigningKey,omitempty"`

	// AllowedAudiences is the list of audiences accepted in identity assertions from
	// this provider. Empty means any audience is accepted.
	// +optional
	AllowedAudiences []string `json:"allowedAudiences,omitempty"`

	// ValidationRules is an ordered list of CEL expressions evaluated against
	// identity assertions from this provider. All rules must pass for an assertion
	// to be accepted. Empty means no additional rules beyond type-level validation.
	// +optional
	ValidationRules []string `json:"validationRules,omitempty"`
}

// IdentityProviderStatus defines the observed state of an IdentityProvider.
type IdentityProviderStatus struct {
	// ObservedGeneration is the generation of the IdentityProvider spec last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions is the list of status conditions for this IdentityProvider.
	// Condition types: Valid, Reachable (OIDC only).
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// IdentityProvider declares an external identity source whose assertions Guardian
// will recognize and validate. One IdentityProvider per external identity source.
// Multiple IdentityBindings may reference the same IdentityProvider.
// guardian-schema.md §7.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=idp
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=".spec.type"
// +kubebuilder:printcolumn:name="Valid",type=string,JSONPath=".status.conditions[?(@.type==\"Valid\")].status"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"
type IdentityProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IdentityProviderSpec   `json:"spec,omitempty"`
	Status IdentityProviderStatus `json:"status,omitempty"`
}

// IdentityProviderList is the list type for IdentityProvider.
//
// +kubebuilder:object:root=true
type IdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []IdentityProvider `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IdentityProvider{}, &IdentityProviderList{})
}
