package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SyncStatus is a typed string declaring the synchronization state of a
// PermissionSnapshotReceipt relative to the management cluster.
type SyncStatus string

const (
	// SyncStatusInSync indicates the local agent has acknowledged the current snapshot.
	SyncStatusInSync SyncStatus = "InSync"

	// SyncStatusOutOfSync indicates the local agent has not yet acknowledged the
	// current snapshot. New PackExecution is blocked on this cluster.
	SyncStatusOutOfSync SyncStatus = "OutOfSync"

	// SyncStatusDegraded indicates persistent failure beyond the extended threshold.
	// No new authorization decisions are permitted. Human intervention required.
	// guardian-schema.md §9.
	SyncStatusDegraded SyncStatus = "DegradedSecurityState"
)

// PermissionSnapshotReceiptSpec defines the desired state of a PermissionSnapshotReceipt.
// Created and maintained exclusively by the runner in agent mode.
// Never authored manually. guardian-schema.md §8.
type PermissionSnapshotReceiptSpec struct {
	// ClusterName is the name of the target cluster this receipt belongs to.
	ClusterName string `json:"clusterName"`

	// SnapshotVersion is the version of the PermissionSnapshot this receipt acknowledges.
	SnapshotVersion string `json:"snapshotVersion"`

	// AcknowledgedAt is the timestamp when the agent acknowledged this snapshot.
	AcknowledgedAt metav1.Time `json:"acknowledgedAt"`
}

// PermissionSnapshotReceiptStatus defines the observed state of a PermissionSnapshotReceipt.
type PermissionSnapshotReceiptStatus struct {
	// LocalProvisioningStatus is a human-readable description of local RBAC provisioning.
	// +optional
	LocalProvisioningStatus string `json:"localProvisioningStatus,omitempty"`

	// LocalArtifacts is the list of RBAC artifact names provisioned from this snapshot.
	// +optional
	LocalArtifacts []string `json:"localArtifacts,omitempty"`

	// SyncStatus is the synchronization state with the management cluster.
	// +optional
	SyncStatus SyncStatus `json:"syncStatus,omitempty"`
}

// PermissionSnapshotReceipt is the target cluster CRD managed by the runner in
// agent mode. It records the current acknowledged PermissionSnapshot and local
// RBAC provisioning status. One per target cluster.
// Exists in ont-system on the target cluster. guardian-schema.md §8.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=psr
type PermissionSnapshotReceipt struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PermissionSnapshotReceiptSpec   `json:"spec,omitempty"`
	Status PermissionSnapshotReceiptStatus `json:"status,omitempty"`
}

// PermissionSnapshotReceiptList is the list type for PermissionSnapshotReceipt.
//
// +kubebuilder:object:root=true
type PermissionSnapshotReceiptList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []PermissionSnapshotReceipt `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PermissionSnapshotReceipt{}, &PermissionSnapshotReceiptList{})
}
