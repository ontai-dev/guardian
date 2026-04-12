package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ontai-dev/seam-core/pkg/lineage"
)

// PermissionScope is a typed string declaring whether permissions are namespaced
// or cluster-scoped.
type PermissionScope string

const (
	// PermissionScopeNamespaced grants permissions within namespaces only.
	PermissionScopeNamespaced PermissionScope = "namespaced"

	// PermissionScopeCluster grants cluster-wide permissions.
	PermissionScopeCluster PermissionScope = "cluster"
)

// Condition type constants for RBACProfile.
const (
	// ConditionTypeRBACProfileProvisioned is the primary gate condition.
	// True exclusively when all validation and compliance checks pass.
	// CS-INV-005: set only by RBACProfileReconciler Step I.
	ConditionTypeRBACProfileProvisioned = "Provisioned"

	// ConditionTypeRBACProfileValidated indicates whether structural validation passed.
	ConditionTypeRBACProfileValidated = "ProfileValidated"

	// ConditionTypeRBACProfilePolicyCompliant indicates whether the profile
	// complies with its governing RBACPolicy.
	ConditionTypeRBACProfilePolicyCompliant = "PolicyCompliant"
)

// Condition reason constants for RBACProfile.
const (
	// ReasonProvisioningComplete is set when all checks pass and provisioned=true.
	ReasonProvisioningComplete = "ProvisioningComplete"

	// ReasonProvisioningFailed is set when structural validation fails.
	ReasonProvisioningFailed = "ProvisioningFailed"

	// ReasonPolicyNotFound is set when the governing RBACPolicy does not exist.
	ReasonPolicyNotFound = "PolicyNotFound"

	// ReasonPolicyViolation is set when compliance check fails.
	ReasonPolicyViolation = "PolicyViolation"

	// ReasonPermissionSetMissing is set when one or more referenced PermissionSets
	// do not exist in the same namespace.
	ReasonPermissionSetMissing = "PermissionSetMissing"

	// ReasonEPGPending is set when the EPG recomputation has been requested but
	// not yet processed.
	ReasonEPGPending = "EPGPending"
)

// PermissionDeclaration declares a permission set reference with scope and cluster constraints.
type PermissionDeclaration struct {
	// PermissionSetRef is the name of a PermissionSet CR in the same namespace.
	// Must not be empty.
	PermissionSetRef string `json:"permissionSetRef"`

	// Scope declares whether these permissions are namespaced or cluster-scoped.
	// Must be one of: namespaced, cluster.
	// +kubebuilder:validation:Enum=namespaced;cluster
	Scope PermissionScope `json:"scope"`

	// Clusters is the list of cluster names this declaration applies to.
	// Empty means all TargetClusters defined on the RBACProfile.
	// +optional
	Clusters []string `json:"clusters,omitempty"`
}

// RBACProfileSpec defines the desired state of a RBACProfile.
type RBACProfileSpec struct {
	// PrincipalRef is the name of the principal this profile governs.
	// Must not be empty.
	PrincipalRef string `json:"principalRef"`

	// TargetClusters is the list of cluster names this profile grants access to.
	// Must not be empty — a profile with no target clusters grants access to nothing.
	TargetClusters []string `json:"targetClusters"`

	// PermissionDeclarations is the list of permission declarations for this profile.
	// Must not be empty.
	PermissionDeclarations []PermissionDeclaration `json:"permissionDeclarations"`

	// RBACPolicyRef is the name of the governing RBACPolicy in the same namespace.
	// Must not be empty.
	RBACPolicyRef string `json:"rbacPolicyRef"`

	// DomainIdentityRef is the optional reference to the DomainIdentity at
	// core.ontai.dev that this operator's service account traces to.
	// Format: {name} — references a DomainIdentity in the domain-core.
	// Set by compiler enable for Seam operator RBACProfiles.
	// Required for Seam family operators. Optional for third-party components.
	// +kubebuilder:validation:Optional
	DomainIdentityRef string `json:"domainIdentityRef,omitempty"`

	// Lineage is the sealed causal chain record for this root declaration.
	// Authored once at object creation time and immutable thereafter.
	// The admission webhook rejects any update that modifies this field after creation.
	// seam-core-schema.md §5, CLAUDE.md §14 Decision 1.
	// +optional
	Lineage *lineage.SealedCausalChain `json:"lineage,omitempty"`
}

// RBACProfileStatus defines the observed state of a RBACProfile.
type RBACProfileStatus struct {
	// ObservedGeneration is the generation of the RBACProfile spec last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Provisioned is the primary gate field. True exclusively when all validation
	// and compliance checks pass. Set only by RBACProfileReconciler. CS-INV-005.
	// +optional
	Provisioned bool `json:"provisioned,omitempty"`

	// Conditions is the list of status conditions for this RBACProfile.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ValidationSummary is a human-readable summary of the current state.
	// +optional
	ValidationSummary string `json:"validationSummary,omitempty"`

	// EPGVersion is the version of the EPG computation that last included this
	// profile. Populated by EPGReconciler. Empty until Session 5.
	// +optional
	EPGVersion string `json:"epgVersion,omitempty"`

	// LastProvisionedAt is the timestamp when Provisioned last transitioned to true.
	// Cleared (set to nil) when the profile regresses to Provisioned=false.
	// +optional
	LastProvisionedAt *metav1.Time `json:"lastProvisionedAt,omitempty"`
}

// RBACProfile is the per-component per-tenant permission declaration.
// Validated against the governing RBACPolicy before provisioned=true is set.
// No operator is enabled until its RBACProfile reaches provisioned=true. INV-003.
// guardian-schema.md §7.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=rbp
// +kubebuilder:printcolumn:name="Name",type=string,JSONPath=`.metadata.name`
// +kubebuilder:printcolumn:name="Provisioned",type=boolean,JSONPath=`.status.provisioned`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type RBACProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RBACProfileSpec   `json:"spec,omitempty"`
	Status RBACProfileStatus `json:"status,omitempty"`
}

// RBACProfileList is the list type for RBACProfile.
//
// +kubebuilder:object:root=true
type RBACProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []RBACProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RBACProfile{}, &RBACProfileList{})
}
