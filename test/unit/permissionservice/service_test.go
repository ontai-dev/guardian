package permissionservice_test

import (
	"context"
	"testing"
	"time"

	"github.com/ontai-dev/guardian/internal/epg"
	"github.com/ontai-dev/guardian/internal/permissionservice"
)

// makeStore returns an InMemoryEPGStore populated with the given result.
func makeStore(result epg.EPGComputationResult) *permissionservice.InMemoryEPGStore {
	s := permissionservice.NewInMemoryEPGStore()
	s.Update(result)
	return s
}

// testResult builds a simple EPGComputationResult for cluster "ccs-dev" with two principals.
//
// principal-a can: get/list pods (core) and get secrets (core, only "my-secret").
// principal-b can: get/list/watch deployments (apps) and create configmaps (core).
func testResult() epg.EPGComputationResult {
	return epg.EPGComputationResult{
		ComputedAt:     time.Now(),
		TargetClusters: []string{"ccs-dev"},
		PermissionsByCluster: map[string][]epg.PrincipalPermissions{
			"ccs-dev": {
				{
					PrincipalName: "principal-a",
					ClusterName:   "ccs-dev",
					EffectiveRules: []epg.EffectiveRule{
						{
							APIGroup:  "",
							Resource:  "pods",
							Verbs:     []string{"get", "list"},
						},
						{
							APIGroup:      "",
							Resource:      "secrets",
							Verbs:         []string{"get"},
							ResourceNames: []string{"my-secret"},
						},
					},
				},
				{
					PrincipalName: "principal-b",
					ClusterName:   "ccs-dev",
					EffectiveRules: []epg.EffectiveRule{
						{
							APIGroup: "apps",
							Resource: "deployments",
							Verbs:    []string{"get", "list", "watch"},
						},
						{
							APIGroup: "",
							Resource: "configmaps",
							Verbs:    []string{"create"},
						},
					},
				},
			},
		},
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// CheckPermission
// ──────────────────────────────────────────────────────────────────────────────

func TestCheckPermission_AllowedExactMatch(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	resp, err := svc.CheckPermission(context.Background(), &permissionservice.CheckPermissionRequest{
		Principal: "principal-a",
		Cluster:   "ccs-dev",
		APIGroup:  "",
		Resource:  "pods",
		Verb:      "get",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected Allowed=true; reason=%q", resp.Reason)
	}
}

func TestCheckPermission_DeniedVerbNotInRule(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	resp, err := svc.CheckPermission(context.Background(), &permissionservice.CheckPermissionRequest{
		Principal: "principal-a",
		Cluster:   "ccs-dev",
		APIGroup:  "",
		Resource:  "pods",
		Verb:      "delete", // not in effective rule
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allowed {
		t.Errorf("expected Allowed=false; got Allowed=true")
	}
}

func TestCheckPermission_DeniedUnknownPrincipal(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	resp, err := svc.CheckPermission(context.Background(), &permissionservice.CheckPermissionRequest{
		Principal: "nobody",
		Cluster:   "ccs-dev",
		APIGroup:  "",
		Resource:  "pods",
		Verb:      "get",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allowed {
		t.Errorf("expected Allowed=false for unknown principal")
	}
}

func TestCheckPermission_DeniedUnknownCluster(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	resp, err := svc.CheckPermission(context.Background(), &permissionservice.CheckPermissionRequest{
		Principal: "principal-a",
		Cluster:   "nonexistent-cluster",
		APIGroup:  "",
		Resource:  "pods",
		Verb:      "get",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allowed {
		t.Errorf("expected Allowed=false for unknown cluster")
	}
}

func TestCheckPermission_ResourceName_AllowedExplicitMatch(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	// principal-a can get secrets but only "my-secret"
	resp, err := svc.CheckPermission(context.Background(), &permissionservice.CheckPermissionRequest{
		Principal:    "principal-a",
		Cluster:      "ccs-dev",
		APIGroup:     "",
		Resource:     "secrets",
		Verb:         "get",
		ResourceName: "my-secret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected Allowed=true for explicit resource name match; reason=%q", resp.Reason)
	}
}

func TestCheckPermission_ResourceName_DeniedNameNotInList(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	// principal-a can get "my-secret" only, not "other-secret"
	resp, err := svc.CheckPermission(context.Background(), &permissionservice.CheckPermissionRequest{
		Principal:    "principal-a",
		Cluster:      "ccs-dev",
		APIGroup:     "",
		Resource:     "secrets",
		Verb:         "get",
		ResourceName: "other-secret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allowed {
		t.Errorf("expected Allowed=false for resource name not in allowed list")
	}
}

func TestCheckPermission_StoreNotReady(t *testing.T) {
	svc := permissionservice.NewService(permissionservice.NewInMemoryEPGStore())
	resp, err := svc.CheckPermission(context.Background(), &permissionservice.CheckPermissionRequest{
		Principal: "principal-a",
		Cluster:   "ccs-dev",
		APIGroup:  "",
		Resource:  "pods",
		Verb:      "get",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allowed {
		t.Errorf("expected Allowed=false when store is not ready")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// ListPermissions
// ──────────────────────────────────────────────────────────────────────────────

func TestListPermissions_ReturnsRulesForKnownPrincipal(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	resp, err := svc.ListPermissions(context.Background(), &permissionservice.ListPermissionsRequest{
		Principal: "principal-a",
		Cluster:   "ccs-dev",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Rules) != 2 {
		t.Errorf("expected 2 rules for principal-a; got %d", len(resp.Rules))
	}
}

func TestListPermissions_EmptyForUnknownPrincipal(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	resp, err := svc.ListPermissions(context.Background(), &permissionservice.ListPermissionsRequest{
		Principal: "nobody",
		Cluster:   "ccs-dev",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Rules) != 0 {
		t.Errorf("expected 0 rules for unknown principal; got %d", len(resp.Rules))
	}
}

func TestListPermissions_EmptyWhenStoreNotReady(t *testing.T) {
	svc := permissionservice.NewService(permissionservice.NewInMemoryEPGStore())
	resp, err := svc.ListPermissions(context.Background(), &permissionservice.ListPermissionsRequest{
		Principal: "principal-a",
		Cluster:   "ccs-dev",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Rules) != 0 {
		t.Errorf("expected empty rules when store not ready; got %d", len(resp.Rules))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// WhoCanDo
// ──────────────────────────────────────────────────────────────────────────────

func TestWhoCanDo_ReturnsPrincipalWithPermission(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	resp, err := svc.WhoCanDo(context.Background(), &permissionservice.WhoCanDoRequest{
		Cluster:  "ccs-dev",
		APIGroup: "",
		Resource: "pods",
		Verb:     "get",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Principals) != 1 || resp.Principals[0] != "principal-a" {
		t.Errorf("expected [principal-a]; got %v", resp.Principals)
	}
}

func TestWhoCanDo_ReturnsMultiplePrincipals(t *testing.T) {
	// Build a result where both principals can get configmaps.
	result := testResult()
	result.PermissionsByCluster["ccs-dev"][0].EffectiveRules = append(
		result.PermissionsByCluster["ccs-dev"][0].EffectiveRules,
		epg.EffectiveRule{APIGroup: "", Resource: "configmaps", Verbs: []string{"get"}},
	)

	svc := permissionservice.NewService(makeStore(result))
	resp, err := svc.WhoCanDo(context.Background(), &permissionservice.WhoCanDoRequest{
		Cluster:  "ccs-dev",
		APIGroup: "",
		Resource: "configmaps",
		Verb:     "get",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Principals) != 1 {
		t.Errorf("expected 1 principal (principal-a); got %v", resp.Principals)
	}
}

func TestWhoCanDo_EmptyWhenNobodyCanDo(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	resp, err := svc.WhoCanDo(context.Background(), &permissionservice.WhoCanDoRequest{
		Cluster:  "ccs-dev",
		APIGroup: "",
		Resource: "nodes",
		Verb:     "get",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Principals) != 0 {
		t.Errorf("expected empty principals; got %v", resp.Principals)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// ExplainDecision
// ──────────────────────────────────────────────────────────────────────────────

func TestExplainDecision_AllowedWithMatchedRule(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	resp, err := svc.ExplainDecision(context.Background(), &permissionservice.ExplainDecisionRequest{
		Principal: "principal-b",
		Cluster:   "ccs-dev",
		APIGroup:  "apps",
		Resource:  "deployments",
		Verb:      "watch",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected Allowed=true; reason=%q", resp.Reason)
	}
	if resp.MatchedRule == nil {
		t.Error("expected MatchedRule to be non-nil when Allowed=true")
	}
	if resp.MatchedRule != nil && resp.MatchedRule.Resource != "deployments" {
		t.Errorf("expected MatchedRule.Resource=deployments; got %q", resp.MatchedRule.Resource)
	}
}

func TestExplainDecision_DeniedNoMatchedRule(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	resp, err := svc.ExplainDecision(context.Background(), &permissionservice.ExplainDecisionRequest{
		Principal: "principal-a",
		Cluster:   "ccs-dev",
		APIGroup:  "apps",
		Resource:  "deployments",
		Verb:      "get",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allowed {
		t.Errorf("expected Allowed=false")
	}
	if resp.MatchedRule != nil {
		t.Errorf("expected MatchedRule to be nil when Allowed=false")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// WS3 corrected tests — explicit coverage for the six required scenarios.
// These tests document the behavioural contract regardless of existing coverage.
// ──────────────────────────────────────────────────────────────────────────────

// TestCheckPermission_SubjectWithActiveBinding_ReturnsAuthorized verifies that
// CheckPermission returns Allowed=true for a subject with an active permission
// mapping (IdentityBinding → principal → EPG rule). Not an error.
func TestCheckPermission_SubjectWithActiveBinding_ReturnsAuthorized(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	resp, err := svc.CheckPermission(context.Background(), &permissionservice.CheckPermissionRequest{
		Principal: "principal-b",
		Cluster:   "ccs-dev",
		APIGroup:  "apps",
		Resource:  "deployments",
		Verb:      "list",
	})
	if err != nil {
		t.Fatalf("CheckPermission returned unexpected error: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected Allowed=true for subject with active binding; reason=%q", resp.Reason)
	}
	if resp.Reason == "" {
		t.Error("expected non-empty Reason in authorized response")
	}
}

// TestCheckPermission_NoMatchingBinding_ReturnsDeniedNotError verifies that
// CheckPermission returns Allowed=false with a human-readable reason when the
// subject has no matching principal in the EPG. The response must not be an error.
func TestCheckPermission_NoMatchingBinding_ReturnsDeniedNotError(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	resp, err := svc.CheckPermission(context.Background(), &permissionservice.CheckPermissionRequest{
		Principal: "unknown-subject",
		Cluster:   "ccs-dev",
		APIGroup:  "",
		Resource:  "pods",
		Verb:      "get",
	})
	// Must return (response, nil) — not (nil, error).
	if err != nil {
		t.Fatalf("expected nil error for missing binding; got: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response for missing binding")
	}
	if resp.Allowed {
		t.Error("expected Allowed=false for subject with no matching binding")
	}
	if resp.Reason == "" {
		t.Error("expected non-empty Reason in denied response")
	}
}

// TestCheckPermission_MalformedSubjectIdentifier_NoPanic verifies that
// CheckPermission returns a structured denied response (not a panic) when
// the subject identifier is empty or otherwise malformed.
func TestCheckPermission_MalformedSubjectIdentifier_NoPanic(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))

	cases := []struct {
		name      string
		principal string
	}{
		{"empty string", ""},
		{"whitespace only", "   "},
		{"null-byte embedded", "princi\x00pal"},
		{"very long identifier", string(make([]byte, 4096))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("CheckPermission panicked for principal %q: %v", tc.principal, r)
				}
			}()
			resp, err := svc.CheckPermission(context.Background(), &permissionservice.CheckPermissionRequest{
				Principal: tc.principal,
				Cluster:   "ccs-dev",
				APIGroup:  "",
				Resource:  "pods",
				Verb:      "get",
			})
			if err != nil {
				t.Fatalf("expected nil error for malformed identifier %q; got: %v", tc.principal, err)
			}
			if resp == nil {
				t.Fatalf("expected non-nil response for malformed identifier %q", tc.principal)
			}
			if resp.Allowed {
				t.Errorf("expected Allowed=false for malformed identifier %q", tc.principal)
			}
		})
	}
}

// TestListPermissions_AllPermissionsForValidSubject verifies that ListPermissions
// returns all effective rules for a subject with an active IdentityBinding.
func TestListPermissions_AllPermissionsForValidSubject(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	resp, err := svc.ListPermissions(context.Background(), &permissionservice.ListPermissionsRequest{
		Principal: "principal-b",
		Cluster:   "ccs-dev",
	})
	if err != nil {
		t.Fatalf("ListPermissions returned unexpected error: %v", err)
	}
	// principal-b has two rules: deployments (apps) and configmaps (core).
	if len(resp.Rules) != 2 {
		t.Errorf("expected 2 rules for principal-b; got %d", len(resp.Rules))
	}
	// All rules must be non-empty.
	for i, rule := range resp.Rules {
		if rule.Resource == "" {
			t.Errorf("rule[%d] has empty Resource", i)
		}
		if len(rule.Verbs) == 0 {
			t.Errorf("rule[%d] has no Verbs", i)
		}
	}
}

// TestWhoCanDo_AllSubjectsThatCanPerformAction verifies that WhoCanDo returns
// every principal that has the requested permission — including all matching principals
// when multiple have the same effective rule.
func TestWhoCanDo_AllSubjectsThatCanPerformAction(t *testing.T) {
	// Extend testResult so both principals can list configmaps.
	result := testResult()
	result.PermissionsByCluster["ccs-dev"][0].EffectiveRules = append(
		result.PermissionsByCluster["ccs-dev"][0].EffectiveRules,
		epg.EffectiveRule{APIGroup: "", Resource: "configmaps", Verbs: []string{"list"}},
	)
	result.PermissionsByCluster["ccs-dev"][1].EffectiveRules = append(
		result.PermissionsByCluster["ccs-dev"][1].EffectiveRules,
		epg.EffectiveRule{APIGroup: "", Resource: "configmaps", Verbs: []string{"list"}},
	)

	svc := permissionservice.NewService(makeStore(result))
	resp, err := svc.WhoCanDo(context.Background(), &permissionservice.WhoCanDoRequest{
		Cluster:  "ccs-dev",
		APIGroup: "",
		Resource: "configmaps",
		Verb:     "list",
	})
	if err != nil {
		t.Fatalf("WhoCanDo returned unexpected error: %v", err)
	}
	if len(resp.Principals) != 2 {
		t.Errorf("expected 2 principals; got %v", resp.Principals)
	}
	principalSet := make(map[string]bool)
	for _, p := range resp.Principals {
		principalSet[p] = true
	}
	if !principalSet["principal-a"] {
		t.Error("expected principal-a in WhoCanDo response")
	}
	if !principalSet["principal-b"] {
		t.Error("expected principal-b in WhoCanDo response")
	}
}

// TestExplainDecision_FullPolicyEvaluationChain verifies that ExplainDecision returns
// a complete explanation: Allowed=true, a non-empty Reason, and a non-nil MatchedRule
// with the correct resource, API group, and verbs. This is the QuantAI integration point
// for human-gate review. guardian-schema.md §10, guardian-design.md §5.
func TestExplainDecision_FullPolicyEvaluationChain(t *testing.T) {
	svc := permissionservice.NewService(makeStore(testResult()))
	resp, err := svc.ExplainDecision(context.Background(), &permissionservice.ExplainDecisionRequest{
		Principal: "principal-a",
		Cluster:   "ccs-dev",
		APIGroup:  "",
		Resource:  "pods",
		Verb:      "list",
	})
	if err != nil {
		t.Fatalf("ExplainDecision returned unexpected error: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected Allowed=true; reason=%q", resp.Reason)
	}
	if resp.Reason == "" {
		t.Error("expected non-empty Reason in ExplainDecision response")
	}
	if resp.MatchedRule == nil {
		t.Fatal("expected non-nil MatchedRule when Allowed=true")
	}
	if resp.MatchedRule.Resource != "pods" {
		t.Errorf("expected MatchedRule.Resource=pods; got %q", resp.MatchedRule.Resource)
	}
	if resp.MatchedRule.APIGroup != "" {
		t.Errorf("expected MatchedRule.APIGroup=<core>; got %q", resp.MatchedRule.APIGroup)
	}
	if len(resp.MatchedRule.Verbs) == 0 {
		t.Error("expected non-empty Verbs in MatchedRule")
	}
}

func TestExplainDecision_StoreNotReady(t *testing.T) {
	svc := permissionservice.NewService(permissionservice.NewInMemoryEPGStore())
	resp, err := svc.ExplainDecision(context.Background(), &permissionservice.ExplainDecisionRequest{
		Principal: "principal-a",
		Cluster:   "ccs-dev",
		APIGroup:  "",
		Resource:  "pods",
		Verb:      "get",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allowed {
		t.Errorf("expected Allowed=false when store not ready")
	}
}
