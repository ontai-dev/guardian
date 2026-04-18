// Package webhook_test contains unit tests for the EvaluateLineageImmutability
// pure function defined in lineage_immutability.go.
//
// These tests verify all decision branches: kind filtering, operation filtering
// (CREATE/DELETE always allowed), lineage equality comparison (both nil, both
// equal, one nil, both present but different), and the invariant reference in
// denial reason. CLAUDE.md §14 Decision 1, seam-core-schema.md §5.
package webhook_test

import (
	"strings"
	"testing"

	"github.com/ontai-dev/guardian/internal/webhook"
)

// --- InterceptedLineageKinds coverage ---

// Test L1 — All five guardian root-declaration CRD kinds are intercepted.
func TestInterceptedLineageKinds_ContainsAllFive(t *testing.T) {
	expected := []string{
		"RBACPolicy",
		"RBACProfile",
		"IdentityBinding",
		"IdentityProvider",
		"PermissionSet",
	}
	for _, kind := range expected {
		if !webhook.InterceptedLineageKinds[kind] {
			t.Errorf("expected kind %q to be in InterceptedLineageKinds", kind)
		}
	}
	if len(webhook.InterceptedLineageKinds) != len(expected) {
		t.Errorf("expected exactly %d intercepted lineage kinds; got %d",
			len(expected), len(webhook.InterceptedLineageKinds))
	}
}

// --- Non-intercepted kinds ---

// Test L2 — Non-intercepted kind: always allowed regardless of operation or lineage change.
func TestEvaluateLineageImmutability_NonInterceptedKind_Allowed(t *testing.T) {
	decision := webhook.EvaluateLineageImmutability(webhook.LineageImmutabilityRequest{
		Kind:          "Deployment",
		Operation:     webhook.OperationUpdate,
		OldLineageRaw: []byte(`{"rootKind":"TalosCluster"}`),
		NewLineageRaw: []byte(`{"rootKind":"SomethingElse"}`),
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for non-intercepted kind; got reason %q", decision.Reason)
	}
}

// Test L3 — Non-intercepted kind: allowed even if both lineage fields differ.
func TestEvaluateLineageImmutability_NonInterceptedKind_DifferentLineage_Allowed(t *testing.T) {
	decision := webhook.EvaluateLineageImmutability(webhook.LineageImmutabilityRequest{
		Kind:          "ConfigMap",
		Operation:     webhook.OperationUpdate,
		OldLineageRaw: nil,
		NewLineageRaw: []byte(`{"rootKind":"PackExecution"}`),
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for non-intercepted kind ConfigMap; got reason %q", decision.Reason)
	}
}

// --- CREATE is always allowed ---

// Test L4 — RBACPolicy CREATE: always allowed regardless of lineage content.
// Lineage is authored at creation time — CREATE is the authoring event.
func TestEvaluateLineageImmutability_RBACPolicy_Create_Allowed(t *testing.T) {
	decision := webhook.EvaluateLineageImmutability(webhook.LineageImmutabilityRequest{
		Kind:          "RBACPolicy",
		Operation:     webhook.OperationCreate,
		OldLineageRaw: nil,
		NewLineageRaw: []byte(`{"rootKind":"RBACPolicy","rootName":"test"}`),
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for RBACPolicy CREATE; got reason %q", decision.Reason)
	}
}

// Test L5 — All five intercepted kinds: CREATE is always allowed.
func TestEvaluateLineageImmutability_AllInterceptedKinds_Create_Allowed(t *testing.T) {
	kinds := []string{"RBACPolicy", "RBACProfile", "IdentityBinding", "IdentityProvider", "PermissionSet"}
	for _, kind := range kinds {
		decision := webhook.EvaluateLineageImmutability(webhook.LineageImmutabilityRequest{
			Kind:          kind,
			Operation:     webhook.OperationCreate,
			OldLineageRaw: nil,
			NewLineageRaw: []byte(`{"rootKind":"Foo"}`),
		})
		if !decision.Allowed {
			t.Errorf("kind %q: expected Allowed=true for CREATE; got reason %q", kind, decision.Reason)
		}
	}
}

// --- UPDATE with unchanged lineage ---

// Test L6 — RBACPolicy UPDATE: both lineage absent (nil) → allowed.
// A resource without lineage (optional field absent) may be updated freely
// as long as lineage remains absent.
func TestEvaluateLineageImmutability_RBACPolicy_Update_BothNil_Allowed(t *testing.T) {
	decision := webhook.EvaluateLineageImmutability(webhook.LineageImmutabilityRequest{
		Kind:          "RBACPolicy",
		Operation:     webhook.OperationUpdate,
		OldLineageRaw: nil,
		NewLineageRaw: nil,
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for RBACPolicy UPDATE with both lineage nil; got reason %q", decision.Reason)
	}
}

// Test L7 — RBACPolicy UPDATE: both lineage identical JSON → allowed.
func TestEvaluateLineageImmutability_RBACPolicy_Update_IdenticalLineage_Allowed(t *testing.T) {
	lineage := []byte(`{"rootKind":"RBACPolicy","rootName":"test-policy","rootNamespace":"security-system","rootUID":"abc-123","creatingOperator":{"name":"guardian","version":"v0.1.0"},"creationRationale":"SecurityEnforcement","rootGenerationAtCreation":1}`)
	decision := webhook.EvaluateLineageImmutability(webhook.LineageImmutabilityRequest{
		Kind:          "RBACPolicy",
		Operation:     webhook.OperationUpdate,
		OldLineageRaw: lineage,
		NewLineageRaw: lineage,
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for RBACPolicy UPDATE with identical lineage; got reason %q", decision.Reason)
	}
}

// Test L8 — UPDATE: semantically equal JSON with different whitespace → allowed.
// The comparison must be structural (via JSON unmarshal), not byte-level.
func TestEvaluateLineageImmutability_Update_SemanticallySameLineage_Allowed(t *testing.T) {
	old := []byte(`{"rootKind":"RBACPolicy","rootName":"test"}`)
	newVal := []byte(`{ "rootKind": "RBACPolicy", "rootName": "test" }`)
	decision := webhook.EvaluateLineageImmutability(webhook.LineageImmutabilityRequest{
		Kind:          "RBACPolicy",
		Operation:     webhook.OperationUpdate,
		OldLineageRaw: old,
		NewLineageRaw: newVal,
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for semantically equal lineage (whitespace differs); got reason %q", decision.Reason)
	}
}

// --- UPDATE with changed lineage → denied ---

// Test L9 — RBACPolicy UPDATE: lineage absent → present (nil → non-nil) → denied.
// Adding lineage post-creation is a sealed-field mutation. CLAUDE.md §14 Decision 1.
func TestEvaluateLineageImmutability_RBACPolicy_Update_NilToPresent_Denied(t *testing.T) {
	decision := webhook.EvaluateLineageImmutability(webhook.LineageImmutabilityRequest{
		Kind:          "RBACPolicy",
		Operation:     webhook.OperationUpdate,
		OldLineageRaw: nil,
		NewLineageRaw: []byte(`{"rootKind":"RBACPolicy"}`),
	})
	if decision.Allowed {
		t.Error("expected Allowed=false for RBACPolicy UPDATE adding lineage (nil→present)")
	}
	if decision.Reason == "" {
		t.Error("expected non-empty reason for denied decision")
	}
}

// Test L10 — RBACPolicy UPDATE: lineage present → absent (present → nil) → denied.
// Removing lineage post-creation is also a sealed-field mutation.
func TestEvaluateLineageImmutability_RBACPolicy_Update_PresentToNil_Denied(t *testing.T) {
	decision := webhook.EvaluateLineageImmutability(webhook.LineageImmutabilityRequest{
		Kind:          "RBACPolicy",
		Operation:     webhook.OperationUpdate,
		OldLineageRaw: []byte(`{"rootKind":"RBACPolicy"}`),
		NewLineageRaw: nil,
	})
	if decision.Allowed {
		t.Error("expected Allowed=false for RBACPolicy UPDATE removing lineage (present→nil)")
	}
}

// Test L11 — RBACPolicy UPDATE: lineage field value changed → denied.
// Mutating an existing lineage is the primary immutability violation.
func TestEvaluateLineageImmutability_RBACPolicy_Update_FieldChanged_Denied(t *testing.T) {
	old := []byte(`{"rootKind":"RBACPolicy","rootName":"original"}`)
	newVal := []byte(`{"rootKind":"RBACPolicy","rootName":"modified"}`)
	decision := webhook.EvaluateLineageImmutability(webhook.LineageImmutabilityRequest{
		Kind:          "RBACPolicy",
		Operation:     webhook.OperationUpdate,
		OldLineageRaw: old,
		NewLineageRaw: newVal,
	})
	if decision.Allowed {
		t.Error("expected Allowed=false for RBACPolicy UPDATE with modified lineage field")
	}
}

// Test L12 — All five intercepted kinds: UPDATE with changed lineage → denied.
func TestEvaluateLineageImmutability_AllInterceptedKinds_Update_Changed_Denied(t *testing.T) {
	kinds := []string{"RBACPolicy", "RBACProfile", "IdentityBinding", "IdentityProvider", "PermissionSet"}
	for _, kind := range kinds {
		old := []byte(`{"rootKind":"` + kind + `","rootName":"original"}`)
		newVal := []byte(`{"rootKind":"` + kind + `","rootName":"changed"}`)
		decision := webhook.EvaluateLineageImmutability(webhook.LineageImmutabilityRequest{
			Kind:          kind,
			Operation:     webhook.OperationUpdate,
			OldLineageRaw: old,
			NewLineageRaw: newVal,
		})
		if decision.Allowed {
			t.Errorf("kind %q: expected Allowed=false for UPDATE with modified lineage", kind)
		}
	}
}

// --- Denial reason content ---

// Test L13 — Denial reason references CLAUDE.md §14 Decision 1.
func TestEvaluateLineageImmutability_DeniedReason_ReferencesDecision1(t *testing.T) {
	decision := webhook.EvaluateLineageImmutability(webhook.LineageImmutabilityRequest{
		Kind:          "RBACPolicy",
		Operation:     webhook.OperationUpdate,
		OldLineageRaw: nil,
		NewLineageRaw: []byte(`{"rootKind":"RBACPolicy"}`),
	})
	if decision.Allowed {
		t.Fatal("expected denied decision")
	}
	if !strings.Contains(decision.Reason, "CLAUDE.md") {
		t.Errorf("expected reason to reference CLAUDE.md; got %q", decision.Reason)
	}
	if !strings.Contains(decision.Reason, "Decision 1") {
		t.Errorf("expected reason to reference Decision 1; got %q", decision.Reason)
	}
}

// Test L14 — Denial reason includes the kind name for operator observability.
func TestEvaluateLineageImmutability_DeniedReason_IncludesKind(t *testing.T) {
	kinds := []string{"RBACPolicy", "RBACProfile", "IdentityBinding", "IdentityProvider", "PermissionSet"}
	for _, kind := range kinds {
		decision := webhook.EvaluateLineageImmutability(webhook.LineageImmutabilityRequest{
			Kind:          kind,
			Operation:     webhook.OperationUpdate,
			OldLineageRaw: nil,
			NewLineageRaw: []byte(`{"rootKind":"X"}`),
		})
		if decision.Allowed {
			t.Fatalf("kind %q: expected denied decision", kind)
		}
		if !strings.Contains(decision.Reason, kind) {
			t.Errorf("kind %q: expected reason to include kind name; got %q", kind, decision.Reason)
		}
	}
}

// Test L15 — Reason is empty when allowed.
func TestEvaluateLineageImmutability_AllowedReason_IsEmpty(t *testing.T) {
	decision := webhook.EvaluateLineageImmutability(webhook.LineageImmutabilityRequest{
		Kind:          "RBACPolicy",
		Operation:     webhook.OperationUpdate,
		OldLineageRaw: nil,
		NewLineageRaw: nil,
	})
	if !decision.Allowed {
		t.Fatal("expected allowed decision")
	}
	if decision.Reason != "" {
		t.Errorf("expected empty reason for allowed decision; got %q", decision.Reason)
	}
}

// Test L16 — JSON "null" value is treated as absent lineage (equal to nil).
// Kubernetes API machinery may serialize an absent optional field as JSON null.
func TestEvaluateLineageImmutability_Update_NullAndNil_Treated_Equal_Allowed(t *testing.T) {
	decision := webhook.EvaluateLineageImmutability(webhook.LineageImmutabilityRequest{
		Kind:          "PermissionSet",
		Operation:     webhook.OperationUpdate,
		OldLineageRaw: []byte("null"),
		NewLineageRaw: nil,
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true when old=null and new=nil (both absent); got reason %q", decision.Reason)
	}
}
