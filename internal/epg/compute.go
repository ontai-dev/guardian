package epg

import (
	"fmt"
	"sort"
	"time"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

// ComputeEPG computes the Effective Permission Graph from the provided inputs.
//
// All inputs are already-fetched Go types. No Kubernetes API calls are made
// inside this function. The computation is idempotent: given the same inputs,
// it always produces the same output. guardian-design.md §2.
//
// Parameters:
//   - provisioned: RBACProfiles with Status.Provisioned=true. Caller guarantees this.
//   - policies: map of policy name to RBACPolicy (key=name, all policies governing provisioned profiles).
//   - permissionSets: map of permset name to PermissionSet (key=name, all permsets referenced anywhere).
//   - identityBindings: valid IdentityBindings (IdentityBindingValid=True). Carried as input
//     for future PermissionService correlation; not used in current computation.
//
// Returns an EPGComputationResult and nil error on success. Returns a non-nil error
// if any referenced policy or permission set cannot be found in the provided maps.
func ComputeEPG(
	provisioned []securityv1alpha1.RBACProfile,
	policies map[string]securityv1alpha1.RBACPolicy,
	permissionSets map[string]securityv1alpha1.PermissionSet,
	identityBindings []securityv1alpha1.IdentityBinding,
) (EPGComputationResult, error) {
	// Phase 1 — Guard: empty provisioned slice produces an empty but valid result.
	if len(provisioned) == 0 {
		return EPGComputationResult{
			ComputedAt:           time.Now(),
			TargetClusters:       []string{},
			PermissionsByCluster: make(map[string][]PrincipalPermissions),
		}, nil
	}

	// Phase 2 — For each provisioned RBACProfile, compute effective permissions.
	// Accumulate into a flat slice; merging happens in Phase 3.
	type entry struct {
		principal string
		cluster   string
		rules     []EffectiveRule
	}
	var entries []entry

	for _, profile := range provisioned {
		// Sub-step 2a: resolve governing RBACPolicy.
		policy, ok := policies[profile.Spec.RBACPolicyRef]
		if !ok {
			return EPGComputationResult{}, fmt.Errorf(
				"ComputeEPG: profile %q references RBACPolicy %q which was not provided",
				profile.Name, profile.Spec.RBACPolicyRef,
			)
		}

		// Sub-step 2b: resolve ceiling PermissionSet.
		ceilingPS, ok := permissionSets[policy.Spec.MaximumPermissionSetRef]
		if !ok {
			return EPGComputationResult{}, fmt.Errorf(
				"ComputeEPG: policy %q references ceiling PermissionSet %q which was not provided",
				policy.Name, policy.Spec.MaximumPermissionSetRef,
			)
		}

		// Sub-step 2c: aggregate all declared PermissionRules for this profile,
		// scoped per-cluster as declared.
		type clusterRules struct {
			clusters []string
			rules    []securityv1alpha1.PermissionRule
		}
		var declarations []clusterRules

		for _, decl := range profile.Spec.PermissionDeclarations {
			ps, ok := permissionSets[decl.PermissionSetRef]
			if !ok {
				return EPGComputationResult{}, fmt.Errorf(
					"ComputeEPG: profile %q declaration references PermissionSet %q which was not provided",
					profile.Name, decl.PermissionSetRef,
				)
			}

			// Determine effective cluster scope for this declaration.
			var effectiveClusters []string
			if len(decl.Clusters) == 0 {
				// Empty Clusters means all of the profile's TargetClusters.
				effectiveClusters = profile.Spec.TargetClusters
			} else {
				// Restricted to the intersection of decl.Clusters and TargetClusters.
				targetSet := make(map[string]struct{}, len(profile.Spec.TargetClusters))
				for _, c := range profile.Spec.TargetClusters {
					targetSet[c] = struct{}{}
				}
				for _, c := range decl.Clusters {
					if _, ok := targetSet[c]; ok {
						effectiveClusters = append(effectiveClusters, c)
					}
				}
			}

			if len(effectiveClusters) > 0 {
				declarations = append(declarations, clusterRules{
					clusters: effectiveClusters,
					rules:    ps.Spec.Permissions,
				})
			}
		}

		// Sub-step 2d: for each effective cluster, compute ceiling intersection.
		// First, build a per-cluster set of all declared rules.
		clusterDeclaredRules := make(map[string][]securityv1alpha1.PermissionRule)
		for _, cr := range declarations {
			for _, cluster := range cr.clusters {
				clusterDeclaredRules[cluster] = append(clusterDeclaredRules[cluster], cr.rules...)
			}
		}

		for cluster, declaredRules := range clusterDeclaredRules {
			effective := IntersectWithCeiling(declaredRules, ceilingPS.Spec.Permissions)
			entries = append(entries, entry{
				principal: profile.Spec.PrincipalRef,
				cluster:   cluster,
				rules:     effective,
			})
		}
	}

	// Phase 3 — Merge entries for the same (principal, cluster) pair.
	type principalCluster struct{ principal, cluster string }
	mergedOrder := make([]principalCluster, 0)
	mergedRules := make(map[principalCluster][]EffectiveRule)

	for _, e := range entries {
		pc := principalCluster{e.principal, e.cluster}
		if existing, ok := mergedRules[pc]; ok {
			// Merge: union verbs for matching (APIGroup, Resource) pairs, then
			// re-deduplicate.
			combined := append(existing, e.rules...) //nolint:gocritic // intentional append to new slice
			mergedRules[pc] = deduplicateAndSort(combined)
		} else {
			mergedRules[pc] = e.rules
			mergedOrder = append(mergedOrder, pc)
		}
	}

	// Phase 4 — Build EPGComputationResult.
	clusterSet := make(map[string]struct{})
	permsByCluster := make(map[string][]PrincipalPermissions)

	for _, pc := range mergedOrder {
		clusterSet[pc.cluster] = struct{}{}
		permsByCluster[pc.cluster] = append(permsByCluster[pc.cluster], PrincipalPermissions{
			PrincipalName:  pc.principal,
			ClusterName:    pc.cluster,
			EffectiveRules: mergedRules[pc],
		})
	}

	targetClusters := make([]string, 0, len(clusterSet))
	for c := range clusterSet {
		targetClusters = append(targetClusters, c)
	}
	sort.Strings(targetClusters)

	return EPGComputationResult{
		ComputedAt:           time.Now(),
		TargetClusters:       targetClusters,
		PermissionsByCluster: permsByCluster,
	}, nil
}

// deduplicateAndSort deduplicates EffectiveRules by (APIGroup, Resource), unions
// verbs, applies ResourceNames intersection, then sorts by APIGroup/Resource.
func deduplicateAndSort(rules []EffectiveRule) []EffectiveRule {
	result := deduplicateRules(rules)
	sort.Slice(result, func(i, j int) bool {
		if result[i].APIGroup != result[j].APIGroup {
			return result[i].APIGroup < result[j].APIGroup
		}
		return result[i].Resource < result[j].Resource
	})
	return result
}

