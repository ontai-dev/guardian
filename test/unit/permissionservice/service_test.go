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
