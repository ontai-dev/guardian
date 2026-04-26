// Package controller_test -- management-cluster back-fill tests.
//
// The management cluster is treated as a tenant by the back-fill runnable (Decision F).
// Its namespace is seam-tenant-{mgmt-cluster-name}, e.g. seam-tenant-ccs-mgmt.
//
// Under the three-layer RBAC hierarchy (guardian-schema.md §19):
//   - Backfill skips namespaces without cluster-policy (CS-INV-009).
//   - Backfill re-applies unprovisioned component-labeled RBACProfiles.
//   - Backfill skips provisioned=true profiles (CS-INV-005).
//   - No per-component RBACPolicy or PermissionSet is created (CS-INV-008).
//
// guardian-schema.md §6, §18, §19, Decision F, CS-INV-005, CS-INV-008.
package controller_test

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
)

// TestRBACProfileBackfill_ManagementCluster_SkipsWhenClusterPolicyAbsent verifies
// that RunOnce skips seam-tenant-ccs-mgmt when cluster-policy is absent.
// ClusterRBACPolicyReconciler must provision it first. CS-INV-009.
func TestRBACProfileBackfill_ManagementCluster_SkipsWhenClusterPolicyAbsent(t *testing.T) {
	const ns = "seam-tenant-ccs-mgmt"
	c := newBackfillClient(t,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}},
		// No cluster-policy pre-created.
		backfillComponentProfile("cilium", ns, "ccs-mgmt", false),
	)
	r := &controller.RBACProfileBackfillRunnable{Client: c}

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	// Profile must not have been re-applied (cluster-policy absent means namespace skipped).
	// No per-component PermissionSet or RBACPolicy should have been created.
	psList := &securityv1alpha1.PermissionSetList{}
	if err := c.List(context.Background(), psList, client.InNamespace(ns)); err != nil {
		t.Fatalf("list PermissionSets: %v", err)
	}
	if len(psList.Items) != 0 {
		t.Errorf("expected 0 PermissionSets (skip when cluster-policy absent); got %d", len(psList.Items))
	}
}

// TestRBACProfileBackfill_ManagementCluster_ReappliesUnprovisionedProfile verifies
// that RunOnce re-applies an unprovisioned component profile when cluster-policy exists.
// guardian-schema.md §6, CS-INV-008: only RBACProfile is created, not RBACPolicy or PermissionSet.
func TestRBACProfileBackfill_ManagementCluster_ReappliesUnprovisionedProfile(t *testing.T) {
	const (
		ns      = "seam-tenant-ccs-mgmt"
		cluster = "ccs-mgmt"
		comp    = "cilium"
	)
	c := newBackfillClient(t,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}},
		backfillClusterPolicy(ns, cluster),
		backfillComponentProfile(comp, ns, cluster, false),
	)
	r := &controller.RBACProfileBackfillRunnable{Client: c}

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	// RBACProfile must still exist (re-applied via SSA).
	profile := &securityv1alpha1.RBACProfile{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: comp, Namespace: ns}, profile); err != nil {
		t.Fatalf("RBACProfile not found after re-apply: %v", err)
	}
	if profile.Spec.RBACPolicyRef != "cluster-policy" {
		t.Errorf("rbacPolicyRef: got %q want cluster-policy", profile.Spec.RBACPolicyRef)
	}

	// No per-component RBACPolicy must exist. guardian-schema.md §19 Layer 3, CS-INV-008.
	policy := &securityv1alpha1.RBACPolicy{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: comp + "-policy", Namespace: ns}, policy); err == nil {
		t.Error("per-component RBACPolicy must not be created by backfill under three-layer hierarchy")
	}

	// No per-component PermissionSet must exist.
	ps := &securityv1alpha1.PermissionSet{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: comp, Namespace: ns}, ps); err == nil {
		t.Error("per-component PermissionSet must not be created by backfill under three-layer hierarchy")
	}
}

// TestRBACProfileBackfill_ManagementCluster_SkipsProvisionedProfile verifies that
// RunOnce does not re-apply an already provisioned component profile. CS-INV-005.
func TestRBACProfileBackfill_ManagementCluster_SkipsProvisionedProfile(t *testing.T) {
	const (
		ns      = "seam-tenant-ccs-mgmt"
		cluster = "ccs-mgmt"
		comp    = "cilium"
	)
	c := newBackfillClient(t,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}},
		backfillClusterPolicy(ns, cluster),
		backfillComponentProfile(comp, ns, cluster, true),
	)
	r := &controller.RBACProfileBackfillRunnable{Client: c}

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	profileList := &securityv1alpha1.RBACProfileList{}
	if err := c.List(context.Background(), profileList,
		client.InNamespace(ns),
		client.MatchingLabels{"ontai.dev/policy-type": "component"},
	); err != nil {
		t.Fatalf("list profiles: %v", err)
	}
	if len(profileList.Items) != 1 {
		t.Errorf("expected exactly 1 profile (no new creation); got %d", len(profileList.Items))
	}
}

// TestRBACProfileBackfill_ManagementCluster_Idempotent verifies that two RunOnce calls
// produce the same result as one: no duplicate objects, no error. CS-INV-005.
func TestRBACProfileBackfill_ManagementCluster_Idempotent(t *testing.T) {
	const (
		ns      = "seam-tenant-ccs-mgmt"
		cluster = "ccs-mgmt"
		comp    = "cilium"
	)
	c := newBackfillClient(t,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}},
		backfillClusterPolicy(ns, cluster),
		backfillComponentProfile(comp, ns, cluster, false),
	)
	r := &controller.RBACProfileBackfillRunnable{Client: c}

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("first RunOnce returned error: %v", err)
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("second RunOnce returned error: %v", err)
	}

	profileList := &securityv1alpha1.RBACProfileList{}
	if err := c.List(context.Background(), profileList, client.InNamespace(ns)); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	if len(profileList.Items) != 1 {
		t.Errorf("expected exactly 1 RBACProfile after idempotent pass; got %d", len(profileList.Items))
	}
}

// TestRBACProfileBackfill_ManagementCluster_OrphanCleanup_Stub documents that orphan
// cleanup is not yet implemented for backfill. Orphaned profiles are cleaned up by
// ClusterRBACPolicyReconciler cascade deletion on TalosCluster deletion.
func TestRBACProfileBackfill_ManagementCluster_OrphanCleanup_Stub(t *testing.T) {
	t.Skip("requires orphan cleanup implementation and BACKLOG-ORPHAN-CLEANUP closed")
}
