package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EnforcementMode controls how policy violations are handled by the admission webhook.
// guardian-schema.md §7 RBACPolicy.
type EnforcementMode string

const (
	// EnforcementModeStrict causes violations to be rejected at admission.
	// This is the default production mode. Violations produce a hard block.
	EnforcementModeStrict EnforcementMode = "strict"

	// EnforcementModeAudit causes violations to be logged but not rejected.
	// Used during policy rollout to observe impact before enforcement.
	EnforcementModeAudit EnforcementMode = "audit"
)

// SubjectScope declares the class of principals this policy governs.
// guardian-schema.md §7 RBACPolicy.
type SubjectScope string

const (
	// SubjectScopePlatform applies to platform operators and system components
	// (e.g., guardian, platform, wrapper, conductor).
	SubjectScopePlatform SubjectScope = "platform"

	// SubjectScopeTenant applies to tenant principals and their associated
	// IdentityBindings.
	SubjectScopeTenant SubjectScope = "tenant"
)

// Condition type constants for RBACPolicy. Used in status.Conditions[].Type.
const (
	// ConditionTypeRBACPolicyValid indicates whether the policy structure is valid.
	// True = valid. False = structural validation failed.
	ConditionTypeRBACPolicyValid = "RBACPolicyValid"

	// ConditionTypeRBACPolicyDegraded indicates whether the policy is in a
	// degraded state. True = degraded. False = healthy.
	ConditionTypeRBACPolicyDegraded = "RBACPolicyDegraded"
)

// Condition reason constants for RBACPolicy.
const (
	// ReasonValidationPassed is set when ValidateRBACPolicySpec returns Valid=true.
	ReasonValidationPassed = "ValidationPassed"

	// ReasonValidationFailed is set when ValidateRBACPolicySpec returns Valid=false.
	ReasonValidationFailed = "ValidationFailed"

	// ReasonPermissionSetNotFound is set when the MaximumPermissionSetRef references
	// a PermissionSet CR that does not exist. Reserved for future use — the existence
	// check is not yet implemented pending PermissionSet type definition (Session 4).
	ReasonPermissionSetNotFound = "PermissionSetNotFound"

	// ReasonStructureInvalid is set when the RBACPolicySpec fails structural checks
	// (invalid enum values, malformed cluster names).
	ReasonStructureInvalid = "StructureInvalid"
)

// RBACPolicySpec defines the desired state of a RBACPolicy.
// RBACPolicy is the governing policy for RBACProfiles within its scope.
// Profiles that declare permissions exceeding this policy are rejected at admission.
// guardian-schema.md §7.
type RBACPolicySpec struct {
	// SubjectScope declares the class of principals this policy governs.
	// Must be one of: platform, tenant.
	// +kubebuilder:validation:Enum=platform;tenant
	SubjectScope SubjectScope `json:"subjectScope"`

	// AllowedClusters is the list of cluster names this policy permits operations on.
	// Empty means this policy applies to the management cluster only.
	// Each entry must be a non-empty string with no whitespace.
	// +optional
	AllowedClusters []string `json:"allowedClusters,omitempty"`

	// MaximumPermissionSetRef is the name of a PermissionSet CR that defines the
	// maximum permissions any RBACProfile governed by this policy may declare.
	// Profiles attempting to exceed this bound are rejected at admission.
	// Must be non-empty.
	MaximumPermissionSetRef string `json:"maximumPermissionSetRef"`

	// EnforcementMode controls how violations are handled by the admission webhook.
	// strict: violations are rejected. audit: violations are logged only.
	// +kubebuilder:validation:Enum=strict;audit
	EnforcementMode EnforcementMode `json:"enforcementMode"`
}

// RBACPolicyStatus defines the observed state of a RBACPolicy.
type RBACPolicyStatus struct {
	// ObservedGeneration is the generation of the RBACPolicy spec that was most
	// recently reconciled. Used to detect whether the status reflects the current spec.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions is the list of status conditions for this RBACPolicy.
	// Standard condition types: RBACPolicyValid, RBACPolicyDegraded.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ValidationSummary is a human-readable one-line summary of the current
	// validation state. "Valid." on success. "Validation failed: N check(s) failed."
	// on failure.
	// +optional
	ValidationSummary string `json:"validationSummary,omitempty"`

	// ProfileCount is the number of RBACProfiles currently governed by this policy.
	// Informational — used by operators and humans to understand policy scope.
	// +optional
	ProfileCount int32 `json:"profileCount,omitempty"`
}

// RBACPolicy is the governing policy resource for the security.ontai.dev API group.
// It constrains what RBACProfiles within its scope may declare. Profiles that
// exceed their governing policy are rejected at admission. guardian-schema.md §7.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=rp
// +kubebuilder:printcolumn:name="EnforcementMode",type=string,JSONPath=`.spec.enforcementMode`
// +kubebuilder:printcolumn:name="Valid",type=string,JSONPath=`.status.conditions[?(@.type=="RBACPolicyValid")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type RBACPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RBACPolicySpec   `json:"spec,omitempty"`
	Status RBACPolicyStatus `json:"status,omitempty"`
}

// RBACPolicyList is the list type for RBACPolicy.
//
// +kubebuilder:object:root=true
type RBACPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []RBACPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RBACPolicy{}, &RBACPolicyList{})
}
