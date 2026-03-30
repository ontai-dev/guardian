package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IdentityType is a typed string declaring the class of external identity.
type IdentityType string

const (
	// IdentityTypeOIDC is an OpenID Connect identity.
	IdentityTypeOIDC IdentityType = "oidc"

	// IdentityTypeServiceAccount is a Kubernetes ServiceAccount identity.
	IdentityTypeServiceAccount IdentityType = "serviceAccount"

	// IdentityTypeCertificate is a certificate-based identity.
	IdentityTypeCertificate IdentityType = "certificate"
)

// TrustMethod is a typed string declaring how the identity trust relationship
// is established.
type TrustMethod string

const (
	// TrustMethodMTLS is mutual TLS — the default and preferred trust method.
	TrustMethodMTLS TrustMethod = "mtls"

	// TrustMethodToken is token-based trust. Requires explicit justification and
	// has a hard maximum TTL of 900 seconds (15 minutes). ont-security-schema.md §7.
	TrustMethodToken TrustMethod = "token"
)

// Condition type constants for IdentityBinding.
const (
	// ConditionTypeIdentityBindingValid indicates whether the binding is valid.
	ConditionTypeIdentityBindingValid = "IdentityBindingValid"
)

// Condition reason constants for IdentityBinding.
const (
	// ReasonIdentityBindingValid is set when ValidateIdentityBindingSpec returns Valid=true.
	ReasonIdentityBindingValid = "Valid"

	// ReasonIdentityBindingInvalid is set when ValidateIdentityBindingSpec returns Valid=false.
	ReasonIdentityBindingInvalid = "Invalid"

	// ReasonTokenTTLExceeded is set when TrustMethod=token and TokenMaxTTLSeconds > 900.
	// This is a hard security constraint. ont-security-schema.md §7.
	ReasonTokenTTLExceeded = "TokenTTLExceeded"

	// ReasonTrustMethodMismatch is set when the trust method is incompatible with
	// the identity type (e.g., token trust with certificate identity).
	ReasonTrustMethodMismatch = "TrustMethodMismatch"
)

// OIDCConfig holds the configuration for an OIDC identity.
type OIDCConfig struct {
	// Issuer is the OIDC provider URL. Must not be empty.
	Issuer string `json:"issuer"`

	// ClientID is the client identifier registered with the OIDC provider.
	ClientID string `json:"clientID"`

	// GroupsClaim is the JWT claim name that contains group membership information.
	// +optional
	GroupsClaim string `json:"groupsClaim,omitempty"`
}

// ServiceAccountConfig holds the configuration for a Kubernetes ServiceAccount identity.
type ServiceAccountConfig struct {
	// Name is the ServiceAccount name. Must not be empty.
	Name string `json:"name"`

	// Namespace is the ServiceAccount namespace. Must not be empty.
	Namespace string `json:"namespace"`
}

// CertificateConfig holds the configuration for a certificate-based identity.
type CertificateConfig struct {
	// CommonName is the certificate CN field. Must not be empty.
	CommonName string `json:"commonName"`

	// Organization is the certificate O field.
	// +optional
	Organization string `json:"organization,omitempty"`
}

// IdentityBindingSpec defines the desired state of an IdentityBinding.
type IdentityBindingSpec struct {
	// IdentityType declares the class of external identity being bound.
	// Must be one of: oidc, serviceAccount, certificate.
	// +kubebuilder:validation:Enum=oidc;serviceAccount;certificate
	IdentityType IdentityType `json:"identityType"`

	// PrincipalName maps to the principal name used in RBACProfiles.
	// Must not be empty.
	PrincipalName string `json:"principalName"`

	// TrustMethod declares how the identity trust relationship is established.
	// mtls is the default. token requires justification and max 15-minute TTL.
	// +kubebuilder:validation:Enum=mtls;token
	TrustMethod TrustMethod `json:"trustMethod"`

	// OIDCConfig holds OIDC-specific configuration. Required when IdentityType=oidc.
	// +optional
	OIDCConfig *OIDCConfig `json:"oidcConfig,omitempty"`

	// ServiceAccountConfig holds ServiceAccount-specific configuration.
	// Required when IdentityType=serviceAccount.
	// +optional
	ServiceAccountConfig *ServiceAccountConfig `json:"serviceAccountConfig,omitempty"`

	// CertificateConfig holds certificate-specific configuration.
	// Required when IdentityType=certificate.
	// +optional
	CertificateConfig *CertificateConfig `json:"certificateConfig,omitempty"`

	// TokenMaxTTLSeconds is the maximum token lifetime in seconds.
	// Required when TrustMethod=token. Hard limit: 900 seconds (15 minutes).
	// ont-security-schema.md §7. This is a non-configurable security constraint.
	// +optional
	TokenMaxTTLSeconds int32 `json:"tokenMaxTTLSeconds,omitempty"`
}

// IdentityBindingStatus defines the observed state of an IdentityBinding.
type IdentityBindingStatus struct {
	// ObservedGeneration is the generation of the IdentityBinding spec last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions is the list of status conditions for this IdentityBinding.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ValidationSummary is a human-readable summary of the current state.
	// +optional
	ValidationSummary string `json:"validationSummary,omitempty"`
}

// IdentityBinding maps an external identity to an ONT permission principal.
// ont-security-schema.md §7.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ib
type IdentityBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IdentityBindingSpec   `json:"spec,omitempty"`
	Status IdentityBindingStatus `json:"status,omitempty"`
}

// IdentityBindingList is the list type for IdentityBinding.
//
// +kubebuilder:object:root=true
type IdentityBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []IdentityBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IdentityBinding{}, &IdentityBindingList{})
}
