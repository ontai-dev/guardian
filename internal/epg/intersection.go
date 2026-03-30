package epg

import (
	"sort"

	securityv1alpha1 "github.com/ontai-dev/ont-security/api/v1alpha1"
)

// IntersectWithCeiling computes the effective rules for a set of declared
// PermissionRules against a ceiling PermissionRule set.
//
// The ceiling is the MaximumPermissionSetRef's PermissionSet from the governing
// RBACPolicy. Any declared permission that is not within the ceiling is trimmed.
// Any declared verb not in the ceiling is trimmed. This is the policy enforcement
// mechanism — ont-security-schema.md §7 and ont-security-design.md §2.
//
// Algorithm:
//  1. For each (APIGroup, Resource) pair in the declared rules, find matching
//     ceiling rules. A ceiling rule matches when its APIGroups contains the declared
//     APIGroup (or "*") AND its Resources contains the declared Resource (or "*").
//  2. If no ceiling rule matches: the pair is outside the ceiling — drop it.
//  3. If matched: intersect declared verbs with the union of matching ceiling verbs.
//     Empty intersection means the pair is dropped.
//  4. ResourceNames: intersection of declared and ceiling; empty on either side means
//     "all names" — the more specific side wins.
//  5. Deduplicate results by (APIGroup, Resource), merging verbs and ResourceNames.
//  6. Sort by APIGroup ascending, then Resource ascending.
func IntersectWithCeiling(declared, ceiling []securityv1alpha1.PermissionRule) []EffectiveRule {
	var results []EffectiveRule

	for _, decl := range declared {
		apiGroups := coreGroupIfEmpty(decl.APIGroups)
		for _, apiGroup := range apiGroups {
			for _, resource := range decl.Resources {
				// Find ceiling rules matching this (apiGroup, resource).
				var matching []securityv1alpha1.PermissionRule
				for _, ceil := range ceiling {
					if ceilingMatchesAPIGroup(ceil.APIGroups, apiGroup) &&
						ceilingMatchesResource(ceil.Resources, resource) {
						matching = append(matching, ceil)
					}
				}
				if len(matching) == 0 {
					continue // not in ceiling — drop
				}

				// Union of matching ceiling verbs.
				ceilingVerbs := unionVerbSets(matching)

				// Intersect declared verbs with ceiling verbs.
				effectiveVerbs := verbIntersection(decl.Verbs, ceilingVerbs)
				if len(effectiveVerbs) == 0 {
					continue // no verb overlap — drop
				}
				sort.Strings(effectiveVerbs)

				// ResourceNames: intersection of declared and ceiling union.
				ceilingNames := unionResourceNameSets(matching)
				effectiveNames := resourceNameIntersection(decl.ResourceNames, ceilingNames)
				sort.Strings(effectiveNames)

				results = append(results, EffectiveRule{
					APIGroup:      apiGroup,
					Resource:      resource,
					Verbs:         effectiveVerbs,
					ResourceNames: effectiveNames,
				})
			}
		}
	}

	// Deduplicate by (APIGroup, Resource), merging verbs and ResourceNames.
	results = deduplicateRules(results)

	// Sort by APIGroup ascending, then Resource ascending.
	sort.Slice(results, func(i, j int) bool {
		if results[i].APIGroup != results[j].APIGroup {
			return results[i].APIGroup < results[j].APIGroup
		}
		return results[i].Resource < results[j].Resource
	})

	return results
}

// coreGroupIfEmpty returns [""] if groups is empty or nil.
// An empty APIGroups in a PermissionRule means the core API group.
func coreGroupIfEmpty(groups []string) []string {
	if len(groups) == 0 {
		return []string{""}
	}
	return groups
}

// ceilingMatchesAPIGroup returns true if the ceiling rule's API groups contain
// the declared group or "*".
func ceilingMatchesAPIGroup(ceilGroups []string, declaredGroup string) bool {
	ceilGroups = coreGroupIfEmpty(ceilGroups)
	for _, g := range ceilGroups {
		if g == "*" || g == declaredGroup {
			return true
		}
	}
	return false
}

// ceilingMatchesResource returns true if the ceiling rule's Resources contain
// the declared resource or "*".
func ceilingMatchesResource(ceilResources []string, declaredResource string) bool {
	for _, r := range ceilResources {
		if r == "*" || r == declaredResource {
			return true
		}
	}
	return false
}

// unionVerbSets returns a deduplicated union of all Verbs across the matching ceiling rules.
func unionVerbSets(rules []securityv1alpha1.PermissionRule) map[string]struct{} {
	union := make(map[string]struct{})
	for _, r := range rules {
		for _, v := range r.Verbs {
			union[v] = struct{}{}
		}
	}
	return union
}

// verbIntersection returns the intersection of declared verbs with the ceiling verb set.
func verbIntersection(declared []string, ceilingSet map[string]struct{}) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, v := range declared {
		if _, ok := ceilingSet[v]; ok {
			if _, dup := seen[v]; !dup {
				result = append(result, v)
				seen[v] = struct{}{}
			}
		}
	}
	return result
}

// unionResourceNameSets returns the union of ResourceNames from matching ceiling rules.
// An empty result means "all names" (any matching ceiling rule with empty ResourceNames
// means "all names", which subsumes all specific names).
func unionResourceNameSets(rules []securityv1alpha1.PermissionRule) []string {
	// If any ceiling rule has empty ResourceNames, the union is "all names" → return empty.
	for _, r := range rules {
		if len(r.ResourceNames) == 0 {
			return nil // empty = all names
		}
	}
	// All ceiling rules have non-empty ResourceNames — collect union.
	seen := make(map[string]struct{})
	var union []string
	for _, r := range rules {
		for _, name := range r.ResourceNames {
			if _, dup := seen[name]; !dup {
				union = append(union, name)
				seen[name] = struct{}{}
			}
		}
	}
	return union
}

// resourceNameIntersection computes the effective ResourceNames from declared and ceiling sides.
//
// Semantics:
//   - Both empty: all names allowed (within ceiling).
//   - Declared empty, ceiling non-empty: ceiling names apply (ceiling restricts).
//   - Declared non-empty, ceiling empty: declared names apply (declaration restricts).
//   - Both non-empty: intersection of both slices.
func resourceNameIntersection(declared, ceiling []string) []string {
	if len(declared) == 0 && len(ceiling) == 0 {
		return nil // both empty = all names
	}
	if len(declared) == 0 {
		return ceiling // ceiling restricts to specific names
	}
	if len(ceiling) == 0 {
		return declared // declaration restricts to specific names
	}
	// Both non-empty: intersection.
	ceilSet := make(map[string]struct{}, len(ceiling))
	for _, n := range ceiling {
		ceilSet[n] = struct{}{}
	}
	seen := make(map[string]struct{})
	var result []string
	for _, n := range declared {
		if _, ok := ceilSet[n]; ok {
			if _, dup := seen[n]; !dup {
				result = append(result, n)
				seen[n] = struct{}{}
			}
		}
	}
	return result
}

// deduplicateRules merges EffectiveRules with the same (APIGroup, Resource) pair.
// Verbs are unioned; ResourceNames are intersected using the same semantics as
// resourceNameIntersection.
func deduplicateRules(rules []EffectiveRule) []EffectiveRule {
	type key struct{ apiGroup, resource string }
	order := make([]key, 0, len(rules))
	byKey := make(map[key]*EffectiveRule)

	for i := range rules {
		r := rules[i]
		k := key{r.APIGroup, r.Resource}
		if existing, ok := byKey[k]; ok {
			// Union verbs.
			verbSet := make(map[string]struct{})
			for _, v := range existing.Verbs {
				verbSet[v] = struct{}{}
			}
			for _, v := range r.Verbs {
				if _, dup := verbSet[v]; !dup {
					existing.Verbs = append(existing.Verbs, v)
					verbSet[v] = struct{}{}
				}
			}
			sort.Strings(existing.Verbs)
			// Intersect ResourceNames.
			existing.ResourceNames = resourceNameIntersection(existing.ResourceNames, r.ResourceNames)
			sort.Strings(existing.ResourceNames)
		} else {
			cp := r
			byKey[k] = &cp
			order = append(order, k)
		}
	}

	result := make([]EffectiveRule, 0, len(order))
	for _, k := range order {
		result = append(result, *byKey[k])
	}
	return result
}
