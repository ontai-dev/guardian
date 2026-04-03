// Package epg_test contains unit tests for the IntersectWithCeiling function.
//
// These tests verify ceiling enforcement semantics: verb intersection,
// resource matching, wildcard handling, and ResourceNames resolution.
package epg_test

import (
	"testing"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/epg"
)

// helpers for intersection tests

func ceilRule(apiGroups, resources, verbs []string) securityv1alpha1.PermissionRule {
	return securityv1alpha1.PermissionRule{
		APIGroups: apiGroups,
		Resources: resources,
		Verbs:     verbs,
	}
}

func ceilRuleWithNames(apiGroups, resources, verbs, names []string) securityv1alpha1.PermissionRule {
	return securityv1alpha1.PermissionRule{
		APIGroups:     apiGroups,
		Resources:     resources,
		Verbs:         verbs,
		ResourceNames: names,
	}
}

func declRule(apiGroups, resources, verbs []string) securityv1alpha1.PermissionRule {
	return securityv1alpha1.PermissionRule{
		APIGroups: apiGroups,
		Resources: resources,
		Verbs:     verbs,
	}
}

func declRuleWithNames(apiGroups, resources, verbs, names []string) securityv1alpha1.PermissionRule {
	return securityv1alpha1.PermissionRule{
		APIGroups:     apiGroups,
		Resources:     resources,
		Verbs:         verbs,
		ResourceNames: names,
	}
}

func findRule(rules []epg.EffectiveRule, resource string) *epg.EffectiveRule {
	for i := range rules {
		if rules[i].Resource == resource {
			return &rules[i]
		}
	}
	return nil
}

func verbsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]struct{}, len(a))
	for _, v := range a {
		m[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := m[v]; !ok {
			return false
		}
	}
	return true
}

// Test A — Exact match: declared verbs subset of ceiling verbs → all declared verbs kept.
func TestIntersect_A_ExactMatch_DeclaredSubsetOfCeiling(t *testing.T) {
	declared := []securityv1alpha1.PermissionRule{
		declRule([]string{""}, []string{"pods"}, []string{"get", "list"}),
	}
	ceiling := []securityv1alpha1.PermissionRule{
		ceilRule([]string{""}, []string{"pods"}, []string{"get", "list", "watch"}),
	}

	result := epg.IntersectWithCeiling(declared, ceiling)
	if len(result) != 1 {
		t.Fatalf("expected 1 rule; got %d", len(result))
	}
	if !verbsEqual(result[0].Verbs, []string{"get", "list"}) {
		t.Errorf("expected verbs [get list]; got %v", result[0].Verbs)
	}
}

// Test B — Partial match: declared delete trimmed by ceiling.
func TestIntersect_B_PartialMatch_DeleteTrimmed(t *testing.T) {
	declared := []securityv1alpha1.PermissionRule{
		declRule([]string{""}, []string{"pods"}, []string{"get", "delete"}),
	}
	ceiling := []securityv1alpha1.PermissionRule{
		ceilRule([]string{""}, []string{"pods"}, []string{"get", "list"}),
	}

	result := epg.IntersectWithCeiling(declared, ceiling)
	if len(result) != 1 {
		t.Fatalf("expected 1 rule (get only); got %d rules", len(result))
	}
	if !verbsEqual(result[0].Verbs, []string{"get"}) {
		t.Errorf("expected verbs [get]; got %v", result[0].Verbs)
	}
}

// Test C — No verb overlap → rule dropped.
func TestIntersect_C_NoVerbOverlap_RuleDropped(t *testing.T) {
	declared := []securityv1alpha1.PermissionRule{
		declRule([]string{""}, []string{"pods"}, []string{"delete", "create"}),
	}
	ceiling := []securityv1alpha1.PermissionRule{
		ceilRule([]string{""}, []string{"pods"}, []string{"get", "list"}),
	}

	result := epg.IntersectWithCeiling(declared, ceiling)
	if len(result) != 0 {
		t.Errorf("expected empty result (no verb overlap); got %d rules: %v", len(result), result)
	}
}

// Test D — Resource not in ceiling → rule dropped.
func TestIntersect_D_ResourceNotInCeiling_RuleDropped(t *testing.T) {
	declared := []securityv1alpha1.PermissionRule{
		declRule([]string{""}, []string{"secrets"}, []string{"get"}),
	}
	ceiling := []securityv1alpha1.PermissionRule{
		ceilRule([]string{""}, []string{"pods"}, []string{"get", "list"}),
	}

	result := epg.IntersectWithCeiling(declared, ceiling)
	if findRule(result, "secrets") != nil {
		t.Error("secrets should have been dropped (not in ceiling)")
	}
}

// Test E — ResourceNames: both sides non-empty → intersection of the two lists.
func TestIntersect_E_ResourceNames_BothNonEmpty_Intersection(t *testing.T) {
	declared := []securityv1alpha1.PermissionRule{
		declRuleWithNames([]string{""}, []string{"configmaps"}, []string{"get"},
			[]string{"app-config", "db-config", "extra-config"}),
	}
	ceiling := []securityv1alpha1.PermissionRule{
		ceilRuleWithNames([]string{""}, []string{"configmaps"}, []string{"get", "list"},
			[]string{"app-config", "db-config"}),
	}

	result := epg.IntersectWithCeiling(declared, ceiling)
	if len(result) != 1 {
		t.Fatalf("expected 1 rule; got %d", len(result))
	}
	names := result[0].ResourceNames
	// Should be intersection: {app-config, db-config}. extra-config not in ceiling.
	if len(names) != 2 {
		t.Errorf("expected 2 ResourceNames (app-config, db-config); got %v", names)
	}
	nameSet := make(map[string]struct{})
	for _, n := range names {
		nameSet[n] = struct{}{}
	}
	if _, ok := nameSet["extra-config"]; ok {
		t.Error("extra-config should have been dropped (not in ceiling ResourceNames)")
	}
}

// Test F — ResourceNames: ceiling empty, declared non-empty → declared list retained.
func TestIntersect_F_ResourceNames_CeilingEmpty_DeclaredRetained(t *testing.T) {
	declared := []securityv1alpha1.PermissionRule{
		declRuleWithNames([]string{""}, []string{"pods"}, []string{"get"},
			[]string{"specific-pod"}),
	}
	ceiling := []securityv1alpha1.PermissionRule{
		ceilRule([]string{""}, []string{"pods"}, []string{"get", "list"}),
		// no ResourceNames — ceiling allows all names
	}

	result := epg.IntersectWithCeiling(declared, ceiling)
	if len(result) != 1 {
		t.Fatalf("expected 1 rule; got %d", len(result))
	}
	if len(result[0].ResourceNames) != 1 || result[0].ResourceNames[0] != "specific-pod" {
		t.Errorf("expected ResourceNames=[specific-pod]; got %v", result[0].ResourceNames)
	}
}

// Test G — ResourceNames: ceiling non-empty, declared empty → ceiling list applied.
func TestIntersect_G_ResourceNames_DeclaredEmpty_CeilingApplied(t *testing.T) {
	declared := []securityv1alpha1.PermissionRule{
		declRule([]string{""}, []string{"pods"}, []string{"get"}),
		// no ResourceNames — declared allows all names
	}
	ceiling := []securityv1alpha1.PermissionRule{
		ceilRuleWithNames([]string{""}, []string{"pods"}, []string{"get", "list"},
			[]string{"allowed-pod-1", "allowed-pod-2"}),
	}

	result := epg.IntersectWithCeiling(declared, ceiling)
	if len(result) != 1 {
		t.Fatalf("expected 1 rule; got %d", len(result))
	}
	if len(result[0].ResourceNames) != 2 {
		t.Errorf("expected ceiling ResourceNames [allowed-pod-1, allowed-pod-2]; got %v",
			result[0].ResourceNames)
	}
}

// Test H — Wildcard resource "*" in ceiling matches any declared resource.
func TestIntersect_H_WildcardResource_MatchesAny(t *testing.T) {
	declared := []securityv1alpha1.PermissionRule{
		declRule([]string{""}, []string{"pods"}, []string{"get"}),
		declRule([]string{""}, []string{"services"}, []string{"list"}),
		declRule([]string{""}, []string{"configmaps"}, []string{"watch"}),
	}
	ceiling := []securityv1alpha1.PermissionRule{
		ceilRule([]string{""}, []string{"*"}, []string{"get", "list", "watch"}),
		// wildcard resource — allows any resource
	}

	result := epg.IntersectWithCeiling(declared, ceiling)
	if len(result) != 3 {
		t.Errorf("expected 3 rules (pods, services, configmaps matched by *); got %d: %v",
			len(result), result)
	}
}
