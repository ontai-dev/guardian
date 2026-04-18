// Package epg implements the Effective Permission Graph computation engine.
//
// This package contains pure computation logic and bridge types. It may import
// guardian/api/v1alpha1 for input/output types. It must not import
// sigs.k8s.io/controller-runtime/pkg/client or k8s.io/client-go — all Kubernetes
// API interactions belong in the reconciler layer.
//
// guardian-design.md §2 — EPG Computation Model.
package epg

import "time"

// PrincipalPermissions is the fully computed effective permissions for one
// principal on one cluster after ceiling intersection.
type PrincipalPermissions struct {
	// PrincipalName is the principal identifier from RBACProfile.Spec.PrincipalRef.
	PrincipalName string

	// ClusterName is the target cluster this permission entry applies to.
	ClusterName string

	// EffectiveRules is the list of effective rules after ceiling intersection.
	// The list is sorted by APIGroup ascending, then Resource ascending.
	EffectiveRules []EffectiveRule
}

// EffectiveRule is one allowed operation after ceiling intersection. Verbs are
// sorted and deduplicated. ResourceNames are sorted; empty means all names are allowed.
type EffectiveRule struct {
	// APIGroup is the Kubernetes API group. Empty string means the core API group.
	APIGroup string

	// Resource is the Kubernetes resource type.
	Resource string

	// Verbs is the sorted, deduplicated list of permitted operations.
	Verbs []string

	// ResourceNames restricts the rule to specific resource instances.
	// Empty means all resource names are allowed within the ceiling.
	ResourceNames []string
}

// EPGComputationResult is the full result for one computation run.
type EPGComputationResult struct {
	// ComputedAt is the time when this computation completed.
	ComputedAt time.Time

	// TargetClusters is the sorted list of all cluster names that appear in any
	// provisioned profile. Empty when there are no provisioned profiles.
	TargetClusters []string

	// PermissionsByCluster maps cluster name to the slice of PrincipalPermissions
	// computed for that cluster. Keys correspond to entries in TargetClusters.
	PermissionsByCluster map[string][]PrincipalPermissions
}
