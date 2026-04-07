package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ontai-dev/seam-core/pkg/lineage"
)

// SubjectKind identifies the kind of a Kubernetes subject in a PermissionSnapshot.
// +kubebuilder:validation:Enum=ServiceAccount;User;Group
type SubjectKind string

const (
	SubjectKindServiceAccount SubjectKind = "ServiceAccount"
	SubjectKindUser           SubjectKind = "User"
	SubjectKindGroup          SubjectKind = "Group"
)

// PermissionEntry describes a single permission rule within a subject's grant.
// It mirrors the structure Guardian's PermissionService already evaluates.
type PermissionEntry struct {
	// APIGroups is the list of API groups the rule applies to.
	// Empty string "" refers to the core API group.
	// +optional
	APIGroups []string `json:"apiGroups,omitempty"`

	// Resources is the list of Kubernetes resource types the rule applies to.
	Resources []string `json:"resources"`

	// Verbs is the list of permitted operations (get, list, watch, create, update, patch, delete, deletecollection).
	Verbs []string `json:"verbs"`

	// ResourceNames is an optional list restricting the rule to named resource instances only.
	// Empty means the rule applies to all instances.
	// +optional
	ResourceNames []string `json:"resourceNames,omitempty"`
}

// SubjectEntry is the per-subject permission grant in a PermissionSnapshot.
// Conductor's pull loop filters these entries by SubjectKind and Namespace
// to enforce RBAC on the target cluster.
type SubjectEntry struct {
	// SubjectName is the name of the subject (ServiceAccount name, username, or group name).
	SubjectName string `json:"subjectName"`

	// SubjectKind identifies the kind of subject.
	SubjectKind SubjectKind `json:"subjectKind"`

	// Namespace is the namespace of the subject. Empty for cluster-scoped subjects
	// (Kind=User or Kind=Group) or cluster-wide ServiceAccount grants.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Permissions is the list of permission rules granted to this subject.
	// +optional
	Permissions []PermissionEntry `json:"permissions,omitempty"`
}

// AllowedOperation describes a single permitted operation within the EPG.
// Retained for compatibility with the existing PrincipalPermissions field.
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
// Retained for compatibility with the existing EPGReconciler output.
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
	// TargetCluster is the cluster name this snapshot governs. Used by Conductor's
	// pull loop to filter snapshots scoped to its own cluster.
	TargetCluster string `json:"targetCluster"`

	// Version is the monotonically increasing version string.
	// Format: ISO8601 timestamp at generation time, e.g. "2026-03-30T12:00:00Z".
	Version string `json:"version"`

	// GeneratedAt is the timestamp when this snapshot was generated.
	// Retained for EPGReconciler compatibility. See also SnapshotTimestamp.
	GeneratedAt metav1.Time `json:"generatedAt"`

	// SnapshotTimestamp is the canonical timestamp when this snapshot was generated,
	// used by PermissionSnapshotReconciler to evaluate FreshnessCondition.
	// +optional
	SnapshotTimestamp *metav1.Time `json:"snapshotTimestamp,omitempty"`

	// SigningKeyFingerprint is the fingerprint of the Ed25519 key used to sign this
	// snapshot. Populated by the management cluster Conductor signing loop after
	// writing the ontai.dev/snapshot-signature annotation. Consumers verify which key
	// was used before trusting the signature.
	// +optional
	SigningKeyFingerprint string `json:"signingKeyFingerprint,omitempty"`

	// FreshnessWindowSeconds is the window within which this snapshot is considered
	// fresh. The PermissionSnapshotReconciler sets FreshnessCondition=Stale when the
	// snapshot age exceeds this value. Default 300 (5 minutes).
	// +optional
	// +kubebuilder:default=300
	// +kubebuilder:validation:Minimum=1
	FreshnessWindowSeconds int32 `json:"freshnessWindowSeconds,omitempty"`

	// Subjects is the per-subject permission grant list for the target cluster.
	// Each entry carries the subject identity and the full list of permission rules
	// granted to that subject, mirroring the structure Guardian's PermissionService
	// evaluates. Conductor filters this list to enforce RBAC on the target cluster.
	// +optional
	Subjects []SubjectEntry `json:"subjects,omitempty"`

	// PrincipalPermissions is the per-principal EPG permission map.
	// Populated by the EPGReconciler from the in-memory EPG store.
	// +optional
	PrincipalPermissions []PrincipalPermissionEntry `json:"principalPermissions,omitempty"`

	// Lineage is the sealed causal chain anchoring this snapshot to the root
	// declaration (RBACPolicy or TalosCluster) that triggered its generation.
	// Authored once at creation time and immutable thereafter.
	// CLAUDE.md §14 Decision 1, seam-core-schema.md §5.
	// +optional
	Lineage *lineage.SealedCausalChain `json:"lineage,omitempty"`
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
	// Deprecated: prefer DriftDetected which is set by the drift detection loop.
	// +optional
	Drift bool `json:"drift,omitempty"`

	// LastSeen is the timestamp of the most recent agent acknowledgement.
	// +optional
	LastSeen *metav1.Time `json:"lastSeen,omitempty"`

	// Signed is true when the management cluster Conductor signing loop has written
	// the ontai.dev/snapshot-signature annotation on this object. INV-026.
	// +optional
	Signed bool `json:"signed,omitempty"`

	// DriftDetected is set by Guardian's drift detection loop on the management cluster
	// when the observed RBAC surface on the target cluster diverges from the snapshot
	// content. Mirrors the Compliant condition in boolean form.
	// +optional
	DriftDetected bool `json:"driftDetected,omitempty"`

	// Conditions is the list of standard metav1 conditions on this snapshot.
	// Managed by PermissionSnapshotReconciler.
	// Includes: LineageSynced, Fresh, Compliant.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// PermissionSnapshot is a computed, versioned EPG for a specific target cluster.
// Generated on any input change by the EPGReconciler. Signed by the management
// cluster Conductor. Never manually authored. One per target cluster, replaced
// in-place on recomputation. guardian-schema.md §7.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=psn
// +kubebuilder:printcolumn:name="TargetCluster",type="string",JSONPath=".spec.targetCluster"
// +kubebuilder:printcolumn:name="Signed",type="boolean",JSONPath=".status.signed"
// +kubebuilder:printcolumn:name="Fresh",type="string",JSONPath=".status.conditions[?(@.type=='Fresh')].status"
// +kubebuilder:printcolumn:name="Compliant",type="string",JSONPath=".status.conditions[?(@.type=='Compliant')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
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
