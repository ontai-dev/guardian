package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AllowedOperation describes a single permitted operation within the EPG.
type AllowedOperation struct {
	// APIGroup is the Kubernetes API group this operation applies to.
	// Empty string means the core API group.
	// +optional
	APIGroup string `json:"apiGroup,omitempty"`

	// Resource is the Kubernetes resource type.
	Resource string `json:"resource"`

	// Verbs is the list of permitted operations on the resource.
	Verbs []string `json:"verbs"`

	// Clusters is the list of cluster names this operation applies to.
	// +optional
	Clusters []string `json:"clusters,omitempty"`
}

// PrincipalPermissionEntry is the per-principal permission entry in a PermissionSnapshot.
type PrincipalPermissionEntry struct {
	// PrincipalRef is the principal name this entry governs.
	PrincipalRef string `json:"principalRef"`

	// AllowedOperations is the list of allowed operations for this principal.
	// +optional
	AllowedOperations []AllowedOperation `json:"allowedOperations,omitempty"`
}

// PermissionSnapshotSpec defines the desired state of a PermissionSnapshot.
// This CR is never manually authored — it is generated exclusively by the
// EPGReconciler. guardian-schema.md §7.
type PermissionSnapshotSpec struct {
	// TargetCluster is the cluster name this snapshot governs.
	TargetCluster string `json:"targetCluster"`

	// Version is the monotonically increasing version string.
	// Format: ISO8601 timestamp at generation time, e.g. "2026-03-30T12:00:00Z".
	Version string `json:"version"`

	// GeneratedAt is the timestamp when this snapshot was generated.
	GeneratedAt metav1.Time `json:"generatedAt"`

	// PrincipalPermissions is the per-principal permission map for this cluster.
	// +optional
	PrincipalPermissions []PrincipalPermissionEntry `json:"principalPermissions,omitempty"`
}

// PermissionSnapshotStatus defines the observed state of a PermissionSnapshot.
type PermissionSnapshotStatus struct {
	// ObservedGeneration is the generation of the PermissionSnapshot spec last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ExpectedVersion is the version the management cluster expects agents to acknowledge.
	// +optional
	ExpectedVersion string `json:"expectedVersion,omitempty"`

	// LastAckedVersion is the version last acknowledged by the target cluster agent.
	// +optional
	LastAckedVersion string `json:"lastAckedVersion,omitempty"`

	// Drift is true when LastAckedVersion != ExpectedVersion.
	// +optional
	Drift bool `json:"drift,omitempty"`

	// LastSeen is the timestamp of the most recent agent acknowledgement.
	// +optional
	LastSeen *metav1.Time `json:"lastSeen,omitempty"`
}

// PermissionSnapshot is a computed, versioned EPG for a specific target cluster.
// Generated on any input change by the EPGReconciler. Never manually authored.
// One per target cluster, replaced in-place on recomputation. guardian-schema.md §7.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=psn
type PermissionSnapshot struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PermissionSnapshotSpec   `json:"spec,omitempty"`
	Status PermissionSnapshotStatus `json:"status,omitempty"`
}

// PermissionSnapshotList is the list type for PermissionSnapshot.
//
// +kubebuilder:object:root=true
type PermissionSnapshotList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []PermissionSnapshot `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PermissionSnapshot{}, &PermissionSnapshotList{})
}
