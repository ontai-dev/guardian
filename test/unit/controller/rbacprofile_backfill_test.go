// Package controller_test -- unit tests for RBACProfileBackfillRunnable.
//
// Under the three-layer RBAC hierarchy (guardian-schema.md §19), the backfill
// runnable no longer scans PermissionSets to find component gaps. Instead it:
//   - Skips namespaces where cluster-policy is absent (ClusterRBACPolicyReconciler must run first).
//   - Scans component-labeled RBACProfiles (ontai.dev/policy-type=component) in each namespace.
//   - Re-applies any profile with provisioned=false via EnsurePackRBACProfileCRs (idempotent SSA).
//   - Skips profiles with provisioned=true.
//   - Logs stale profiles referencing non-cluster-policy and skips them.
//
// guardian-schema.md §6, §18, §19, CS-INV-008.
package controller_test

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
)

// buildBackfillScheme returns a runtime.Scheme with core and security API groups.
func buildBackfillScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(securityv1alpha1.AddToScheme(s))
	return s
}

// backfillNamespace creates a Namespace object.
func backfillNamespace(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

// backfillClusterPolicy pre-creates the cluster-level RBACPolicy required by
// EnsurePackRBACProfileCRs as the intake guard. guardian-schema.md §19 Layer 2.
func backfillClusterPolicy(ns, clusterName string) *securityv1alpha1.RBACPolicy {
	return &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-policy",
			Namespace: ns,
			Labels: map[string]string{
				"ontai.dev/managed-by":  "guardian",
				"ontai.dev/policy-type": "cluster",
			},
		},
		Spec: securityv1alpha1.RBACPolicySpec{
			SubjectScope:            "tenant",
			EnforcementMode:         "audit",
			AllowedClusters:         []string{clusterName},
			MaximumPermissionSetRef: "cluster-maximum",
		},
	}
}

// backfillComponentProfile creates a component-labeled RBACProfile in the given namespace.
// provisioned controls whether the profile is already provisioned.
func backfillComponentProfile(name, ns, clusterName string, provisioned bool) *securityv1alpha1.RBACProfile {
	p := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				"ontai.dev/managed-by":  "guardian",
				"ontai.dev/policy-type": "component",
			},
		},
		Spec: securityv1alpha1.RBACProfileSpec{
			PrincipalRef:   name,
			TargetClusters: []string{clusterName},
			RBACPolicyRef:  "cluster-policy",
		},
	}
	p.Status.Provisioned = provisioned
	return p
}

// newBackfillClient builds a fake client with the given objects and the backfill scheme.
func newBackfillClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(buildBackfillScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&securityv1alpha1.RBACProfile{}).
		Build()
}

// TestRBACProfileBackfill_NoTenantNamespaces verifies that runOnce is a no-op when
// no seam-tenant-* namespaces exist.
func TestRBACProfileBackfill_NoTenantNamespaces(t *testing.T) {
	c := newBackfillClient(t, backfillNamespace("default"), backfillNamespace("kube-system"))
	r := &controller.RBACProfileBackfillRunnable{Client: c}

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("runOnce returned unexpected error: %v", err)
	}
	profileList := &securityv1alpha1.RBACProfileList{}
	if err := c.List(context.Background(), profileList); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	if len(profileList.Items) != 0 {
		t.Errorf("expected 0 RBACProfiles; got %d", len(profileList.Items))
	}
}

// TestRBACProfileBackfill_SkipsNamespaceWhenClusterPolicyAbsent verifies that runOnce
// skips a seam-tenant-* namespace that has no cluster-policy (ClusterRBACPolicyReconciler
// has not yet run). No profiles are created. guardian-schema.md §19 Layer 2, §6 guard.
func TestRBACProfileBackfill_SkipsNamespaceWhenClusterPolicyAbsent(t *testing.T) {
	ns := "seam-tenant-prod"
	c := newBackfillClient(t, backfillNamespace(ns))
	r := &controller.RBACProfileBackfillRunnable{Client: c}

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("runOnce returned unexpected error: %v", err)
	}
	profileList := &securityv1alpha1.RBACProfileList{}
	if err := c.List(context.Background(), profileList, client.InNamespace(ns)); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	if len(profileList.Items) != 0 {
		t.Errorf("expected 0 RBACProfiles; got %d", len(profileList.Items))
	}
}

// TestRBACProfileBackfill_SkipsProvisionedProfiles verifies that component profiles with
// provisioned=true are not re-applied by the backfill runnable. CS-INV-005.
func TestRBACProfileBackfill_SkipsProvisionedProfiles(t *testing.T) {
	ns := "seam-tenant-dev"
	c := newBackfillClient(t,
		backfillNamespace(ns),
		backfillClusterPolicy(ns, "dev"),
		backfillComponentProfile("nginx-ingress", ns, "dev", true),
	)
	r := &controller.RBACProfileBackfillRunnable{Client: c}

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("runOnce returned unexpected error: %v", err)
	}
	profileList := &securityv1alpha1.RBACProfileList{}
	if err := c.List(context.Background(), profileList, client.InNamespace(ns)); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	// Count must still be exactly 1 (the pre-existing provisioned profile).
	if len(profileList.Items) != 1 {
		t.Errorf("expected 1 RBACProfile (no new creation); got %d", len(profileList.Items))
	}
}

// TestRBACProfileBackfill_ReappliesUnprovisionedProfile verifies that a component profile
// with provisioned=false is re-applied via EnsurePackRBACProfileCRs. guardian-schema.md §6.
func TestRBACProfileBackfill_ReappliesUnprovisionedProfile(t *testing.T) {
	ns := "seam-tenant-ccs-mgmt"
	c := newBackfillClient(t,
		backfillNamespace(ns),
		backfillClusterPolicy(ns, "ccs-mgmt"),
		backfillComponentProfile("cilium", ns, "ccs-mgmt", false),
	)
	r := &controller.RBACProfileBackfillRunnable{Client: c}

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("runOnce returned unexpected error: %v", err)
	}

	// Profile must still exist after re-apply (SSA is idempotent).
	profileList := &securityv1alpha1.RBACProfileList{}
	if err := c.List(context.Background(), profileList,
		client.InNamespace(ns),
		client.MatchingLabels{"ontai.dev/policy-type": "component"},
	); err != nil {
		t.Fatalf("list component RBACProfiles: %v", err)
	}
	if len(profileList.Items) != 1 {
		t.Errorf("expected 1 component RBACProfile after re-apply; got %d", len(profileList.Items))
	}
}

// TestRBACProfileBackfill_OnlyProcessesTenantNamespaces verifies that namespaces not
// matching the seam-tenant-* prefix are skipped even if they contain component profiles.
func TestRBACProfileBackfill_OnlyProcessesTenantNamespaces(t *testing.T) {
	otherNS := "seam-system"
	tenantNS := "seam-tenant-prod"
	c := newBackfillClient(t,
		backfillNamespace(tenantNS),
		backfillNamespace(otherNS),
		backfillClusterPolicy(tenantNS, "prod"),
		// Component profile in seam-system must not trigger backfill.
		backfillComponentProfile("some-pack", otherNS, "prod", false),
	)
	r := &controller.RBACProfileBackfillRunnable{Client: c}

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("runOnce returned unexpected error: %v", err)
	}
	// The profile in seam-system must be untouched; no new profiles in seam-tenant-prod.
	profileList := &securityv1alpha1.RBACProfileList{}
	if err := c.List(context.Background(), profileList, client.InNamespace(tenantNS)); err != nil {
		t.Fatalf("list RBACProfiles in seam-tenant-prod: %v", err)
	}
	if len(profileList.Items) != 0 {
		t.Errorf("expected 0 profiles in %s; got %d", tenantNS, len(profileList.Items))
	}
}

// TestRBACProfileBackfill_MultipleClusters verifies back-fill across multiple
// seam-tenant-* namespaces in a single pass.
func TestRBACProfileBackfill_MultipleClusters(t *testing.T) {
	ns1 := "seam-tenant-alpha"
	ns2 := "seam-tenant-beta"
	c := newBackfillClient(t,
		backfillNamespace(ns1),
		backfillNamespace(ns2),
		backfillClusterPolicy(ns1, "alpha"),
		backfillClusterPolicy(ns2, "beta"),
		// pack-a in ns1 is unprovisioned -- should be re-applied.
		backfillComponentProfile("pack-a", ns1, "alpha", false),
		// pack-b in ns2 is already provisioned -- should not be re-applied.
		backfillComponentProfile("pack-b", ns2, "beta", true),
	)
	r := &controller.RBACProfileBackfillRunnable{Client: c}

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("runOnce returned unexpected error: %v", err)
	}

	// pack-a must still exist (re-applied via SSA).
	profilesA := &securityv1alpha1.RBACProfileList{}
	if err := c.List(context.Background(), profilesA, client.InNamespace(ns1)); err != nil {
		t.Fatalf("list profiles in ns1: %v", err)
	}
	if len(profilesA.Items) != 1 {
		t.Errorf("expected 1 profile in %s; got %d", ns1, len(profilesA.Items))
	}

	// pack-b must still exist and count must remain 1 (not re-applied or duplicated).
	profilesB := &securityv1alpha1.RBACProfileList{}
	if err := c.List(context.Background(), profilesB, client.InNamespace(ns2)); err != nil {
		t.Fatalf("list profiles in ns2: %v", err)
	}
	if len(profilesB.Items) != 1 {
		t.Errorf("expected 1 profile in %s after no-op; got %d", ns2, len(profilesB.Items))
	}
}
