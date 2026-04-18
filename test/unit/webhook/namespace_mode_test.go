// Package webhook_test contains unit tests for the namespace-mode tiered admission model.
//
// These tests verify the three-tier enforcement model introduced by namespace_mode.go
// and the updated EvaluateAdmission gate order in decision.go:
//
//   - Exempt namespace: all admission is bypassed immediately, before kind or annotation checks.
//   - Observe namespace: full policy evaluation runs; would-deny returns Allowed=true with
//     ObservedDeny=true so the handler can log the observation.
//   - Enforce namespace: full deny posture — the pre-existing behavior.
//   - Zero-value NSMode: treated as Enforce (fail-safe; unknown namespaces are governed).
//
// StaticNamespaceModeResolver is also tested here for coverage of the test helper used
// across integration and unit tests.
//
// INV-020, CS-INV-001, CS-INV-004.
package webhook_test

import (
	"testing"

	"github.com/ontai-dev/guardian/internal/webhook"
)

// --- NSMode: Exempt ---

// Test 22 — Exempt namespace: intercepted RBAC without annotation is allowed.
// The exempt gate fires before kind check, annotation check, and bootstrap window check.
// seam-system and kube-system carry this tier permanently. CS-INV-004.
func TestEvaluateAdmission_NSModeExempt_InterceptedKind_NoAnnotation_Allowed(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:        "Role",
		Operation:   webhook.OperationCreate,
		Annotations: nil,
		NSMode:      webhook.NamespaceModeExempt,
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for exempt namespace; got reason %q", decision.Reason)
	}
	if decision.ObservedDeny {
		t.Error("expected ObservedDeny=false for exempt namespace")
	}
}

// Test 23 — Exempt namespace: all intercepted kinds are allowed without annotation.
func TestEvaluateAdmission_NSModeExempt_AllInterceptedKinds_Allowed(t *testing.T) {
	kinds := []string{"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "ServiceAccount"}
	for _, kind := range kinds {
		decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
			Kind:      kind,
			Operation: webhook.OperationCreate,
			NSMode:    webhook.NamespaceModeExempt,
		})
		if !decision.Allowed {
			t.Errorf("kind %q: expected Allowed=true in exempt namespace; got reason %q",
				kind, decision.Reason)
		}
	}
}

// Test 24 — Exempt namespace: bootstrap window state is irrelevant.
// Exempt fires before the bootstrap window check; the window state does not matter.
func TestEvaluateAdmission_NSModeExempt_BootstrapWindowClosed_StillAllowed(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:                "ClusterRole",
		Operation:           webhook.OperationCreate,
		Annotations:         nil,
		BootstrapWindowOpen: false,
		NSMode:              webhook.NamespaceModeExempt,
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for exempt namespace regardless of bootstrap window; got reason %q",
			decision.Reason)
	}
}

// --- NSMode: Observe ---

// Test 25 — Observe namespace: intercepted RBAC without annotation returns Allowed=true
// with ObservedDeny=true and a non-empty Reason. The handler logs the observation but
// does not deny the request. CS-INV-004.
func TestEvaluateAdmission_NSModeObserve_NoAnnotation_AllowedWithObservedDeny(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:        "Role",
		Operation:   webhook.OperationCreate,
		Annotations: nil,
		NSMode:      webhook.NamespaceModeObserve,
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for observe namespace; got reason %q", decision.Reason)
	}
	if !decision.ObservedDeny {
		t.Error("expected ObservedDeny=true for would-deny in observe namespace")
	}
	if decision.Reason == "" {
		t.Error("expected non-empty Reason in observe mode ObservedDeny response")
	}
}

// Test 26 — Observe namespace: intercepted RBAC with correct annotation is allowed normally.
// ObservedDeny is false — annotation satisfies the policy before reaching the observe gate.
func TestEvaluateAdmission_NSModeObserve_CorrectAnnotation_AllowedNoObservedDeny(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:      "Role",
		Operation: webhook.OperationCreate,
		Annotations: map[string]string{
			webhook.AnnotationRBACOwner: webhook.AnnotationRBACOwnerValue,
		},
		NSMode: webhook.NamespaceModeObserve,
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for annotated Role in observe namespace; got reason %q",
			decision.Reason)
	}
	if decision.ObservedDeny {
		t.Error("expected ObservedDeny=false when annotation is present in observe namespace")
	}
}

// Test 27 — Observe namespace: all intercepted kinds without annotation produce
// ObservedDeny=true. The observation is kind-agnostic.
func TestEvaluateAdmission_NSModeObserve_AllInterceptedKinds_ObservedDeny(t *testing.T) {
	kinds := []string{"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "ServiceAccount"}
	for _, kind := range kinds {
		decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
			Kind:      kind,
			Operation: webhook.OperationCreate,
			NSMode:    webhook.NamespaceModeObserve,
		})
		if !decision.Allowed {
			t.Errorf("kind %q: expected Allowed=true in observe namespace; got reason %q",
				kind, decision.Reason)
		}
		if !decision.ObservedDeny {
			t.Errorf("kind %q: expected ObservedDeny=true in observe namespace", kind)
		}
	}
}

// Test 28 — Observe mode ObservedDeny reason contains the CS-INV-001 reference.
// The reason is the same canonical string as the enforce-mode denial — both come from
// denyReason in decision.go.
func TestEvaluateAdmission_NSModeObserve_ObservedDenyReason_ContainsCSINV001(t *testing.T) {
	import_str := "CS-INV-001"
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:      "ClusterRoleBinding",
		Operation: webhook.OperationCreate,
		NSMode:    webhook.NamespaceModeObserve,
	})
	if !decision.ObservedDeny {
		t.Fatal("expected ObservedDeny=true")
	}
	found := false
	for i := 0; i <= len(decision.Reason)-len(import_str); i++ {
		if decision.Reason[i:i+len(import_str)] == import_str {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ObservedDeny reason to contain %q; got %q", import_str, decision.Reason)
	}
}

// --- NSMode: Enforce (explicit) ---

// Test 29 — Explicit Enforce namespace: intercepted RBAC without annotation is denied.
func TestEvaluateAdmission_NSModeEnforce_NoAnnotation_Denied(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:        "Role",
		Operation:   webhook.OperationCreate,
		Annotations: nil,
		NSMode:      webhook.NamespaceModeEnforce,
	})
	if decision.Allowed {
		t.Error("expected Allowed=false for enforce namespace without annotation")
	}
	if decision.ObservedDeny {
		t.Error("expected ObservedDeny=false for enforce namespace (real deny, not observation)")
	}
}

// --- NSMode: zero value (unlabelled namespace = enforce) ---

// Test 30 — Zero-value NSMode is treated as Enforce. Unlabelled namespaces are governed,
// not exempted. This is the fail-safe: the zero value of a NamespaceMode string is ""
// which does not match Exempt or Observe, so it falls through to the deny path.
func TestEvaluateAdmission_NSModeZeroValue_TreatedAsEnforce(t *testing.T) {
	// NSMode is not set — zero value "".
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:        "Role",
		Operation:   webhook.OperationCreate,
		Annotations: nil,
		// NSMode intentionally omitted — zero value
	})
	if decision.Allowed {
		t.Error("expected Allowed=false for zero-value NSMode (must default to enforce)")
	}
	if decision.ObservedDeny {
		t.Error("expected ObservedDeny=false for zero-value NSMode enforcement")
	}
}

// Test 31 — Zero-value NSMode with correct annotation: still allowed.
// The annotation check happens before the NSMode-based deny path, so a correctly
// annotated resource is always allowed regardless of NSMode.
func TestEvaluateAdmission_NSModeZeroValue_CorrectAnnotation_Allowed(t *testing.T) {
	decision := webhook.EvaluateAdmission(webhook.AdmissionRequest{
		Kind:      "ClusterRole",
		Operation: webhook.OperationCreate,
		Annotations: map[string]string{
			webhook.AnnotationRBACOwner: webhook.AnnotationRBACOwnerValue,
		},
		// NSMode intentionally omitted — zero value
	})
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for annotated resource with zero NSMode; got reason %q",
			decision.Reason)
	}
}

// --- StaticNamespaceModeResolver ---

// Test 32 — StaticNamespaceModeResolver returns the mapped mode for a known namespace.
func TestStaticNamespaceModeResolver_KnownNamespace(t *testing.T) {
	r := &webhook.StaticNamespaceModeResolver{
		Modes: map[string]webhook.NamespaceMode{
			"seam-system": webhook.NamespaceModeExempt,
			"kube-system": webhook.NamespaceModeExempt,
			"test-ns":     webhook.NamespaceModeObserve,
		},
		DefaultMode: webhook.NamespaceModeEnforce,
	}
	cases := []struct {
		ns   string
		want webhook.NamespaceMode
	}{
		{"seam-system", webhook.NamespaceModeExempt},
		{"kube-system", webhook.NamespaceModeExempt},
		{"test-ns", webhook.NamespaceModeObserve},
	}
	for _, tc := range cases {
		got := r.ResolveMode(nil, tc.ns)
		if got != tc.want {
			t.Errorf("namespace %q: got %q, want %q", tc.ns, got, tc.want)
		}
	}
}

// Test 33 — StaticNamespaceModeResolver returns DefaultMode for unknown namespace.
func TestStaticNamespaceModeResolver_UnknownNamespace_DefaultMode(t *testing.T) {
	r := &webhook.StaticNamespaceModeResolver{
		Modes:       map[string]webhook.NamespaceMode{},
		DefaultMode: webhook.NamespaceModeObserve,
	}
	got := r.ResolveMode(nil, "some-unknown-namespace")
	if got != webhook.NamespaceModeObserve {
		t.Errorf("expected DefaultMode %q; got %q", webhook.NamespaceModeObserve, got)
	}
}

// Test 34 — StaticNamespaceModeResolver with zero DefaultMode falls back to Enforce.
// If DefaultMode is not set, unknown namespaces default to Enforce (fail-safe).
func TestStaticNamespaceModeResolver_ZeroDefaultMode_FallsBackToEnforce(t *testing.T) {
	r := &webhook.StaticNamespaceModeResolver{
		Modes: map[string]webhook.NamespaceMode{},
		// DefaultMode intentionally omitted — zero value
	}
	got := r.ResolveMode(nil, "unlabelled-namespace")
	if got != webhook.NamespaceModeEnforce {
		t.Errorf("expected NamespaceModeEnforce for zero DefaultMode; got %q", got)
	}
}
