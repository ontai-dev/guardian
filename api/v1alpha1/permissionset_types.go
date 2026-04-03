package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Verb is a typed Kubernetes RBAC verb.
// Valid values are the eight standard verbs: get, list, watch, create, update,
// patch, delete, deletecollection. guardian-schema.md §7.
//
// +kubebuilder:validation:Enum=get;list;watch;create;update;patch;delete;deletecollection
type Verb string

const (
	VerbGet              Verb = "get"
	VerbList             Verb = "list"
	VerbWatch            Verb = "watch"
	VerbCreate           Verb = "create"
	VerbUpdate           Verb = "update"
	VerbPatch            Verb = "patch"
	VerbDelete           Verb = "delete"
	VerbDeleteCollection Verb = "deletecollection"
)

// PermissionRule defines a single permission rule within a PermissionSet.
// Follows the Kubernetes RBAC rule model.
type PermissionRule struct {
	// APIGroups is the list of API groups this rule applies to.
	// Empty string means the core API group.
	// +optional
	APIGroups []string `json:"apiGroups,omitempty"`

	// Resources is the list of resource types this rule applies to.
	// Must not be empty.
	Resources []string `json:"resources"`

	// Verbs is the list of operations permitted on the resources.
	// Each value must be one of the eight standard Kubernetes RBAC verbs.
	Verbs []Verb `json:"verbs"`

	// ResourceNames is an optional list of names of the resources this rule applies to.
	// Empty means all resource names are allowed.
	// +optional
	ResourceNames []string `json:"resourceNames,omitempty"`
}

// PermissionSetSpec defines the desired state of a PermissionSet.
type PermissionSetSpec struct {
	// Description is a human-readable explanation of the permission set's intent.
	// +optional
	Description string `json:"description,omitempty"`

	// Permissions is the list of permission rules in this set.
	// Must not be empty.
	Permissions []PermissionRule `json:"permissions"`
}

// PermissionSetStatus defines the observed state of a PermissionSet.
type PermissionSetStatus struct {
	// ObservedGeneration is the generation of the PermissionSet spec last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions is the list of status conditions for this PermissionSet.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ProfileReferenceCount is the number of RBACProfiles currently referencing
	// this PermissionSet. Informational only.
	// +optional
	ProfileReferenceCount int32 `json:"profileReferenceCount,omitempty"`
}

// PermissionSet is a named, reusable collection of permissions.
// Platform archetypes (cluster-admin, tenant-admin, pack-executor, viewer) are
// created at initialization time. guardian-schema.md §7.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ps
type PermissionSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PermissionSetSpec   `json:"spec,omitempty"`
	Status PermissionSetStatus `json:"status,omitempty"`
}

// PermissionSetList is the list type for PermissionSet.
//
// +kubebuilder:object:root=true
type PermissionSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []PermissionSet `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PermissionSet{}, &PermissionSetList{})
}
