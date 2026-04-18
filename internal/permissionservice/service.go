package permissionservice

import (
	"context"
	"fmt"
	"strings"

	"github.com/ontai-dev/guardian/internal/epg"
)

// CheckPermissionRequest is the input for CheckPermission.
type CheckPermissionRequest struct {
	// Principal is the identity name (RBACProfile.Spec.PrincipalRef).
	Principal string `json:"principal"`

	// Cluster is the target cluster name.
	Cluster string `json:"cluster"`

	// APIGroup is the Kubernetes API group. Empty string means the core API group.
	APIGroup string `json:"apiGroup"`

	// Resource is the Kubernetes resource type.
	Resource string `json:"resource"`

	// Verb is the requested operation (get, list, watch, create, update, patch,
	// delete, deletecollection).
	Verb string `json:"verb"`

	// ResourceName restricts the check to a specific resource instance name.
	// Empty means the check applies to any resource name.
	// +optional
	ResourceName string `json:"resourceName,omitempty"`
}

// CheckPermissionResponse is the result of CheckPermission.
type CheckPermissionResponse struct {
	// Allowed is true if the permission is granted.
	Allowed bool `json:"allowed"`

	// Reason is a human-readable explanation of the decision.
	Reason string `json:"reason"`
}

// ListPermissionsRequest is the input for ListPermissions.
type ListPermissionsRequest struct {
	// Principal is the identity name.
	Principal string `json:"principal"`

	// Cluster is the target cluster name.
	Cluster string `json:"cluster"`
}

// ListPermissionsResponse is the result of ListPermissions.
type ListPermissionsResponse struct {
	// Rules is the list of effective rules for the principal on the cluster.
	// Empty if the principal has no permissions or is unknown on the cluster.
	Rules []EffectiveRuleDTO `json:"rules"`
}

// WhoCanDoRequest is the input for WhoCanDo.
type WhoCanDoRequest struct {
	// Cluster is the target cluster name.
	Cluster string `json:"cluster"`

	// APIGroup is the Kubernetes API group.
	APIGroup string `json:"apiGroup"`

	// Resource is the Kubernetes resource type.
	Resource string `json:"resource"`

	// Verb is the requested operation.
	Verb string `json:"verb"`
}

// WhoCanDoResponse is the result of WhoCanDo.
type WhoCanDoResponse struct {
	// Principals is the list of principal names that have the requested permission
	// on the cluster. Empty if no principal has the permission.
	Principals []string `json:"principals"`
}

// ExplainDecisionRequest is the input for ExplainDecision.
type ExplainDecisionRequest struct {
	// Principal is the identity name.
	Principal string `json:"principal"`

	// Cluster is the target cluster name.
	Cluster string `json:"cluster"`

	// APIGroup is the Kubernetes API group.
	APIGroup string `json:"apiGroup"`

	// Resource is the Kubernetes resource type.
	Resource string `json:"resource"`

	// Verb is the requested operation.
	Verb string `json:"verb"`
}

// ExplainDecisionResponse is the result of ExplainDecision.
type ExplainDecisionResponse struct {
	// Allowed is true if the permission is granted.
	Allowed bool `json:"allowed"`

	// Reason is a human-readable explanation of the decision.
	Reason string `json:"reason"`

	// MatchedRule is the effective rule that grants the permission.
	// Nil when Allowed is false.
	// +optional
	MatchedRule *EffectiveRuleDTO `json:"matchedRule,omitempty"`
}

// EffectiveRuleDTO is the wire representation of an epg.EffectiveRule.
type EffectiveRuleDTO struct {
	APIGroup      string   `json:"apiGroup"`
	Resource      string   `json:"resource"`
	Verbs         []string `json:"verbs"`
	ResourceNames []string `json:"resourceNames,omitempty"`
}

// Service implements the four PermissionService operations.
// It is backed by an EPGStore; all operations return a "not ready" result when
// no EPG computation has completed yet.
//
// guardian-schema.md §10.
type Service struct {
	store EPGStore
}

// NewService allocates a Service backed by the given EPGStore.
func NewService(store EPGStore) *Service {
	return &Service{store: store}
}

// CheckPermission returns whether the given principal is permitted to perform
// the given verb on the given resource/apiGroup on the given cluster.
//
// If ResourceName is non-empty, the rule must either allow all resource names
// (empty ResourceNames list on the effective rule) or explicitly list the
// requested name.
func (s *Service) CheckPermission(_ context.Context, req *CheckPermissionRequest) (*CheckPermissionResponse, error) {
	result, ok := s.store.GetLatestResult()
	if !ok {
		return &CheckPermissionResponse{
			Allowed: false,
			Reason:  "EPG not yet computed — no authorization decision available",
		}, nil
	}

	rule, found := s.findMatchingRule(result, req.Principal, req.Cluster, req.APIGroup, req.Resource, req.Verb, req.ResourceName)
	if !found {
		return &CheckPermissionResponse{
			Allowed: false,
			Reason: fmt.Sprintf("no effective rule grants %s %s/%s to principal %q on cluster %q",
				req.Verb, req.APIGroup, req.Resource, req.Principal, req.Cluster),
		}, nil
	}
	_ = rule
	return &CheckPermissionResponse{
		Allowed: true,
		Reason:  "allowed by effective rule",
	}, nil
}

// ListPermissions returns all effective rules for the given principal on the
// given cluster. Returns an empty rule list if the principal is unknown or the
// cluster has no EPG data.
func (s *Service) ListPermissions(_ context.Context, req *ListPermissionsRequest) (*ListPermissionsResponse, error) {
	result, ok := s.store.GetLatestResult()
	if !ok {
		return &ListPermissionsResponse{Rules: []EffectiveRuleDTO{}}, nil
	}

	principals, ok := result.PermissionsByCluster[req.Cluster]
	if !ok {
		return &ListPermissionsResponse{Rules: []EffectiveRuleDTO{}}, nil
	}

	for _, pp := range principals {
		if pp.PrincipalName != req.Principal {
			continue
		}
		rules := make([]EffectiveRuleDTO, len(pp.EffectiveRules))
		for i, r := range pp.EffectiveRules {
			rules[i] = toDTO(r)
		}
		return &ListPermissionsResponse{Rules: rules}, nil
	}

	return &ListPermissionsResponse{Rules: []EffectiveRuleDTO{}}, nil
}

// WhoCanDo returns all principals that have the given permission (verb on
// resource/apiGroup) on the given cluster.
func (s *Service) WhoCanDo(_ context.Context, req *WhoCanDoRequest) (*WhoCanDoResponse, error) {
	result, ok := s.store.GetLatestResult()
	if !ok {
		return &WhoCanDoResponse{Principals: []string{}}, nil
	}

	principals, ok := result.PermissionsByCluster[req.Cluster]
	if !ok {
		return &WhoCanDoResponse{Principals: []string{}}, nil
	}

	var matches []string
	for _, pp := range principals {
		for _, rule := range pp.EffectiveRules {
			if rule.APIGroup != req.APIGroup || rule.Resource != req.Resource {
				continue
			}
			for _, v := range rule.Verbs {
				if v == req.Verb {
					matches = append(matches, pp.PrincipalName)
					break
				}
			}
		}
	}
	if matches == nil {
		matches = []string{}
	}
	return &WhoCanDoResponse{Principals: matches}, nil
}

// ExplainDecision returns the authorization decision for the given request and
// the matched effective rule (if allowed). This is the QuantAI integration
// point for human-gate review of AI-proposed operations.
// guardian-schema.md §10.
func (s *Service) ExplainDecision(_ context.Context, req *ExplainDecisionRequest) (*ExplainDecisionResponse, error) {
	result, ok := s.store.GetLatestResult()
	if !ok {
		return &ExplainDecisionResponse{
			Allowed: false,
			Reason:  "EPG not yet computed — no authorization decision available",
		}, nil
	}

	rule, found := s.findMatchingRule(result, req.Principal, req.Cluster, req.APIGroup, req.Resource, req.Verb, "")
	if !found {
		return &ExplainDecisionResponse{
			Allowed: false,
			Reason: fmt.Sprintf("denied: principal %q has no effective rule granting %s on %s/%s in cluster %q",
				req.Principal, req.Verb, req.APIGroup, req.Resource, req.Cluster),
		}, nil
	}

	dto := toDTO(*rule)
	return &ExplainDecisionResponse{
		Allowed:     true,
		Reason:      fmt.Sprintf("allowed: matched effective rule granting verbs [%s] on %s/%s", strings.Join(rule.Verbs, ","), rule.APIGroup, rule.Resource),
		MatchedRule: &dto,
	}, nil
}

// findMatchingRule searches the EPG for an effective rule matching the given
// (principal, cluster, apiGroup, resource, verb, resourceName) tuple.
// resourceName="" means any resource name is acceptable.
// Returns (rule, true) on match; (nil, false) when no rule matches.
func (s *Service) findMatchingRule(
	result *epg.EPGComputationResult,
	principal, cluster, apiGroup, resource, verb, resourceName string,
) (*epg.EffectiveRule, bool) {
	principalList, ok := result.PermissionsByCluster[cluster]
	if !ok {
		return nil, false
	}

	for _, pp := range principalList {
		if pp.PrincipalName != principal {
			continue
		}
		for i, rule := range pp.EffectiveRules {
			if rule.APIGroup != apiGroup || rule.Resource != resource {
				continue
			}
			if !containsVerb(rule.Verbs, verb) {
				continue
			}
			// ResourceName check: if caller specified a name, the rule must either
			// allow all names (empty ResourceNames) or list the requested name.
			if resourceName != "" && len(rule.ResourceNames) > 0 {
				if !containsString(rule.ResourceNames, resourceName) {
					continue
				}
			}
			return &pp.EffectiveRules[i], true
		}
	}
	return nil, false
}

func containsVerb(verbs []string, verb string) bool {
	for _, v := range verbs {
		if v == verb {
			return true
		}
	}
	return false
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func toDTO(r epg.EffectiveRule) EffectiveRuleDTO {
	verbs := make([]string, len(r.Verbs))
	copy(verbs, r.Verbs)
	var names []string
	if len(r.ResourceNames) > 0 {
		names = make([]string, len(r.ResourceNames))
		copy(names, r.ResourceNames)
	}
	return EffectiveRuleDTO{
		APIGroup:      r.APIGroup,
		Resource:      r.Resource,
		Verbs:         verbs,
		ResourceNames: names,
	}
}
