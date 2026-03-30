package epg

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/ontai-dev/ont-security/api/v1alpha1"
)

// BuildPermissionSnapshot constructs a PermissionSnapshot CR from an EPGComputationResult
// scoped to a specific target cluster.
//
// Parameters:
//   - result: the EPGComputationResult from ComputeEPG.
//   - targetCluster: the cluster name to build the snapshot for.
//   - namespace: the namespace to place the snapshot in (security-system).
//   - existingName: the name of an existing PermissionSnapshot for this cluster,
//     or empty string if none exists. When non-empty, the existing name is reused
//     (the snapshot is replaced in-place on recomputation). When empty, a new name
//     is derived as "snapshot-{targetCluster}".
//
// The returned PermissionSnapshot has TypeMeta set for server-side apply compatibility.
// Status is not set — it is managed separately via the status subresource.
func BuildPermissionSnapshot(
	result EPGComputationResult,
	targetCluster string,
	namespace string,
	existingName string,
) *securityv1alpha1.PermissionSnapshot {
	name := existingName
	if name == "" {
		name = fmt.Sprintf("snapshot-%s", targetCluster)
	}

	version := result.ComputedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	generatedAt := metav1.NewTime(result.ComputedAt)

	// Map EPG PrincipalPermissions to API PrincipalPermissionEntry.
	var principalPerms []securityv1alpha1.PrincipalPermissionEntry
	if entries, ok := result.PermissionsByCluster[targetCluster]; ok {
		for _, pp := range entries {
			entry := securityv1alpha1.PrincipalPermissionEntry{
				PrincipalRef:      pp.PrincipalName,
				AllowedOperations: make([]securityv1alpha1.AllowedOperation, 0, len(pp.EffectiveRules)),
			}
			for _, rule := range pp.EffectiveRules {
				entry.AllowedOperations = append(entry.AllowedOperations, securityv1alpha1.AllowedOperation{
					APIGroup: rule.APIGroup,
					Resource: rule.Resource,
					Verbs:    rule.Verbs,
				})
			}
			principalPerms = append(principalPerms, entry)
		}
	}
	if principalPerms == nil {
		principalPerms = []securityv1alpha1.PrincipalPermissionEntry{}
	}

	return &securityv1alpha1.PermissionSnapshot{
		TypeMeta: metav1.TypeMeta{
			APIVersion: securityv1alpha1.GroupVersion.String(),
			Kind:       "PermissionSnapshot",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: securityv1alpha1.PermissionSnapshotSpec{
			TargetCluster:        targetCluster,
			Version:              version,
			GeneratedAt:          generatedAt,
			PrincipalPermissions: principalPerms,
		},
	}
}
