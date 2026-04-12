// Package controller_test contains unit tests for SeamMembershipReconciler.
//
// Tests use the controller-runtime fake client — no etcd or kube-apiserver required.
// Covered cases:
//   - Matching domainIdentityRef with provisioned RBACProfile admits membership.
//   - Mismatched domainIdentityRef blocks admission (Validated=False, DomainIdentityMismatch).
//   - No matching RBACProfile blocks admission (Validated=False, DomainIdentityMismatch, requeue 30s).
//   - Unprovisioned RBACProfile blocks admission (Validated=False, RBACProfileNotProvisioned, requeue 15s).
//   - Already admitted membership reconciles idempotently (AdmittedAt not overwritten).
//   - Infrastructure tier sets PermissionSnapshotRef=snapshot-management.
//   - Application tier sets PermissionSnapshotRef=snapshot-{appIdentityRef}.
package controller_test

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
	seamv1alpha1 "github.com/ontai-dev/seam-core/api/v1alpha1"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildMembershipScheme constructs a scheme with clientgo, guardian, and seam-core types.
func buildMembershipScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(securityv1alpha1.AddToScheme(s))
	utilruntime.Must(seamv1alpha1.AddToScheme(s))
	return s
}

// buildMembershipReconciler creates a SeamMembershipReconciler backed by a fake
// client pre-populated with the given objects.
func buildMembershipReconciler(t *testing.T, objs ...client.Object) *controller.SeamMembershipReconciler {
	t.Helper()
	s := buildMembershipScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&seamv1alpha1.SeamMembership{}).
		Build()
	return &controller.SeamMembershipReconciler{
		Client: c,
		Scheme: s,
	}
}

// reconcileMembership triggers one reconcile cycle for the named SeamMembership.
func reconcileMembership(t *testing.T, r *controller.SeamMembershipReconciler, name, ns string) ctrl.Result {
	t.Helper()
	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: name, Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}
	return result
}

// getMembership re-fetches the SeamMembership from the fake client.
func getMembership(t *testing.T, r *controller.SeamMembershipReconciler, name, ns string) *seamv1alpha1.SeamMembership {
	t.Helper()
	m := &seamv1alpha1.SeamMembership{}
	if err := r.Client.Get(context.Background(), types.NamespacedName{Name: name, Namespace: ns}, m); err != nil {
		t.Fatalf("get SeamMembership: %v", err)
	}
	return m
}

// makeProvisionedProfile builds an RBACProfile with the given principalRef and
// domainIdentityRef, with Status.Provisioned=true.
func makeProvisionedProfile(name, ns, principalRef, domainIdentityRef string) *securityv1alpha1.RBACProfile {
	p := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Generation: 1},
		Spec: securityv1alpha1.RBACProfileSpec{
			PrincipalRef:      principalRef,
			DomainIdentityRef: domainIdentityRef,
			RBACPolicyRef:     "seam-platform-rbac-policy",
			TargetClusters:    []string{"management"},
			PermissionDeclarations: []securityv1alpha1.PermissionDeclaration{
				{PermissionSetRef: "guardian-permissions", Scope: securityv1alpha1.PermissionScopeCluster},
			},
		},
		Status: securityv1alpha1.RBACProfileStatus{
			Provisioned: true,
		},
	}
	return p
}

// makeMembership builds a SeamMembership with the given fields.
func makeMembership(name, ns, appIdentityRef, domainIdentityRef, principalRef, tier string) *seamv1alpha1.SeamMembership {
	return &seamv1alpha1.SeamMembership{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Generation: 1},
		Spec: seamv1alpha1.SeamMembershipSpec{
			AppIdentityRef:    appIdentityRef,
			DomainIdentityRef: domainIdentityRef,
			PrincipalRef:      principalRef,
			Tier:              tier,
		},
	}
}

// findCondition is a test-local helper that searches membership conditions.
func findMembershipCondition(m *seamv1alpha1.SeamMembership, condType string) *metav1.Condition {
	for i := range m.Status.Conditions {
		if m.Status.Conditions[i].Type == condType {
			return &m.Status.Conditions[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestSeamMembershipReconciler_Admitted_InfrastructureTier verifies that a
// SeamMembership with a matching domainIdentityRef and a provisioned RBACProfile
// is admitted with Admitted=true, AdmittedAt set, and
// PermissionSnapshotRef=snapshot-management.
func TestSeamMembershipReconciler_Admitted_InfrastructureTier(t *testing.T) {
	const (
		ns           = "seam-system"
		principal    = "system:serviceaccount:seam-system:guardian"
		domainIDRef  = "guardian"
	)
	profile := makeProvisionedProfile("rbac-guardian", ns, principal, domainIDRef)
	membership := makeMembership("guardian", ns, "guardian", domainIDRef, principal, "infrastructure")

	r := buildMembershipReconciler(t, profile, membership)
	result := reconcileMembership(t, r, "guardian", ns)

	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue after admission; got %v", result.RequeueAfter)
	}

	m := getMembership(t, r, "guardian", ns)

	if !m.Status.Admitted {
		t.Error("expected Admitted=true")
	}
	if m.Status.AdmittedAt == nil {
		t.Error("expected AdmittedAt to be set")
	}
	if m.Status.PermissionSnapshotRef != "snapshot-management" {
		t.Errorf("expected PermissionSnapshotRef=snapshot-management, got %q", m.Status.PermissionSnapshotRef)
	}

	admittedCond := findMembershipCondition(m, seamv1alpha1.ConditionTypeSeamMembershipAdmitted)
	if admittedCond == nil || admittedCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Admitted condition=True; got %v", admittedCond)
	}
	validatedCond := findMembershipCondition(m, seamv1alpha1.ConditionTypeSeamMembershipValidated)
	if validatedCond == nil || validatedCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Validated condition=True; got %v", validatedCond)
	}
}

// TestSeamMembershipReconciler_DomainIdentityMismatch blocks admission when
// the SeamMembership domainIdentityRef does not match the RBACProfile's field.
func TestSeamMembershipReconciler_DomainIdentityMismatch(t *testing.T) {
	const ns = "seam-system"
	principal := "system:serviceaccount:seam-system:platform"
	// Profile has domainIdentityRef=platform; membership claims domainIdentityRef=rogue.
	profile := makeProvisionedProfile("rbac-platform", ns, principal, "platform")
	membership := makeMembership("platform", ns, "platform", "rogue", principal, "infrastructure")

	r := buildMembershipReconciler(t, profile, membership)
	result := reconcileMembership(t, r, "platform", ns)

	// Mismatch: no requeue (caller must fix the spec).
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue after mismatch; got %v", result.RequeueAfter)
	}

	m := getMembership(t, r, "platform", ns)

	if m.Status.Admitted {
		t.Error("expected Admitted=false after domainIdentityRef mismatch")
	}

	cond := findMembershipCondition(m, seamv1alpha1.ConditionTypeSeamMembershipValidated)
	if cond == nil || cond.Status != metav1.ConditionFalse {
		t.Errorf("expected Validated=False; got %v", cond)
	}
	if cond != nil && cond.Reason != seamv1alpha1.ReasonDomainIdentityMismatch {
		t.Errorf("expected reason %q; got %q", seamv1alpha1.ReasonDomainIdentityMismatch, cond.Reason)
	}
}

// TestSeamMembershipReconciler_NoMatchingRBACProfile blocks admission when no
// RBACProfile exists with a matching principalRef. Requeues after 30s.
func TestSeamMembershipReconciler_NoMatchingRBACProfile(t *testing.T) {
	const ns = "seam-system"
	// No RBACProfile in the fake client — membership has no match.
	membership := makeMembership("wrapper", ns, "wrapper", "wrapper",
		"system:serviceaccount:seam-system:wrapper", "infrastructure")

	r := buildMembershipReconciler(t, membership)
	result := reconcileMembership(t, r, "wrapper", ns)

	if result.RequeueAfter != 30*time.Second {
		t.Errorf("expected RequeueAfter=30s; got %v", result.RequeueAfter)
	}

	m := getMembership(t, r, "wrapper", ns)
	if m.Status.Admitted {
		t.Error("expected Admitted=false when no RBACProfile matches")
	}

	cond := findMembershipCondition(m, seamv1alpha1.ConditionTypeSeamMembershipValidated)
	if cond == nil || cond.Status != metav1.ConditionFalse {
		t.Errorf("expected Validated=False; got %v", cond)
	}
	if cond != nil && cond.Reason != seamv1alpha1.ReasonDomainIdentityMismatch {
		t.Errorf("expected reason %q; got %q", seamv1alpha1.ReasonDomainIdentityMismatch, cond.Reason)
	}
}

// TestSeamMembershipReconciler_RBACProfileNotProvisioned blocks admission when
// the matching RBACProfile has provisioned=false. Requeues after 15s.
func TestSeamMembershipReconciler_RBACProfileNotProvisioned(t *testing.T) {
	const ns = "seam-system"
	principal := "system:serviceaccount:seam-system:conductor"

	// Profile exists but provisioned=false.
	profile := makeProvisionedProfile("rbac-conductor", ns, principal, "conductor")
	profile.Status.Provisioned = false

	membership := makeMembership("conductor", ns, "conductor", "conductor", principal, "infrastructure")

	r := buildMembershipReconciler(t, profile, membership)
	result := reconcileMembership(t, r, "conductor", ns)

	if result.RequeueAfter != 15*time.Second {
		t.Errorf("expected RequeueAfter=15s; got %v", result.RequeueAfter)
	}

	m := getMembership(t, r, "conductor", ns)
	if m.Status.Admitted {
		t.Error("expected Admitted=false when RBACProfile not provisioned")
	}

	cond := findMembershipCondition(m, seamv1alpha1.ConditionTypeSeamMembershipValidated)
	if cond == nil || cond.Status != metav1.ConditionFalse {
		t.Errorf("expected Validated=False; got %v", cond)
	}
	if cond != nil && cond.Reason != seamv1alpha1.ReasonRBACProfileNotProvisioned {
		t.Errorf("expected reason %q; got %q", seamv1alpha1.ReasonRBACProfileNotProvisioned, cond.Reason)
	}
}

// TestSeamMembershipReconciler_AlreadyAdmitted_Idempotent verifies that reconciling
// a previously admitted membership does not overwrite AdmittedAt.
func TestSeamMembershipReconciler_AlreadyAdmitted_Idempotent(t *testing.T) {
	const ns = "seam-system"
	principal := "system:serviceaccount:seam-system:seam-core"
	profile := makeProvisionedProfile("rbac-seam-core", ns, principal, "seam-core")

	membership := makeMembership("seam-core", ns, "seam-core", "seam-core", principal, "infrastructure")

	r := buildMembershipReconciler(t, profile, membership)

	// First reconcile — admits.
	reconcileMembership(t, r, "seam-core", ns)
	first := getMembership(t, r, "seam-core", ns)

	if first.Status.AdmittedAt == nil {
		t.Fatal("expected AdmittedAt set after first admission")
	}
	firstAdmittedAt := first.Status.AdmittedAt.DeepCopy()

	// Simulate second reconcile with the same objects — AdmittedAt must not advance.
	reconcileMembership(t, r, "seam-core", ns)
	second := getMembership(t, r, "seam-core", ns)

	if second.Status.AdmittedAt == nil {
		t.Fatal("expected AdmittedAt still set after second reconcile")
	}
	if !second.Status.AdmittedAt.Equal(firstAdmittedAt) {
		t.Errorf("AdmittedAt was overwritten on second reconcile: was %v, now %v",
			firstAdmittedAt, second.Status.AdmittedAt)
	}
}

// TestSeamMembershipReconciler_ApplicationTier verifies that an application-tier
// member receives PermissionSnapshotRef=snapshot-{appIdentityRef}.
func TestSeamMembershipReconciler_ApplicationTier(t *testing.T) {
	const ns = "seam-system"
	principal := "system:serviceaccount:vortex-system:vortex"
	profile := makeProvisionedProfile("rbac-vortex", ns, principal, "vortex")
	membership := makeMembership("vortex", ns, "vortex", "vortex", principal, "application")

	r := buildMembershipReconciler(t, profile, membership)
	reconcileMembership(t, r, "vortex", ns)

	m := getMembership(t, r, "vortex", ns)
	if !m.Status.Admitted {
		t.Error("expected application-tier member to be admitted")
	}
	want := "snapshot-vortex"
	if m.Status.PermissionSnapshotRef != want {
		t.Errorf("expected PermissionSnapshotRef=%q; got %q", want, m.Status.PermissionSnapshotRef)
	}
}

// TestSeamMembershipReconciler_NotFound_NoError verifies that a reconcile request
// for a deleted SeamMembership returns no error and no requeue.
func TestSeamMembershipReconciler_NotFound_NoError(t *testing.T) {
	r := buildMembershipReconciler(t) // empty fake client

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "missing", Namespace: "seam-system"},
	})
	if err != nil {
		t.Fatalf("expected no error for not-found; got %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue for not-found; got %v", result.RequeueAfter)
	}
}
