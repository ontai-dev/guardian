// Package controller_test -- unit tests for RBACProfileBackfillRunnable.
//
// Tests cover:
//   - runOnce with no seam-tenant-* namespaces: no EnsurePackRBACProfileCRs calls.
//   - runOnce with seam-tenant-* namespace containing no PermissionSets: no-op.
//   - runOnce with PermissionSet and existing RBACProfile: no fill.
//   - runOnce with PermissionSet but missing RBACProfile: fills the gap by creating
//     PermissionSet, RBACPolicy, and RBACProfile via EnsurePackRBACProfileCRs.
//   - runOnce with mixed namespace set: only seam-tenant-* namespaces processed.
//   - Decision F: targetCluster derived from seam-tenant-{cluster} suffix.
//
// T-04b, guardian-schema.md §6, CS-INV-005, Decision F.
package controller_test

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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

// backfillPermissionSet creates a PermissionSet in the given namespace.
func backfillPermissionSet(name, ns string) *securityv1alpha1.PermissionSet {
	return &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
	}
}

// backfillRBACProfile creates an RBACProfile in the given namespace.
func backfillRBACProfile(name, ns string) *securityv1alpha1.RBACProfile {
	return &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
	}
}

// newBackfillClient builds a fake client with the given objects and the backfill scheme.
func newBackfillClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(buildBackfillScheme(t)).
		WithObjects(objs...).
		Build()
}

// TestRBACProfileBackfill_NoTenantNamespaces verifies that runOnce is a no-op when
// no seam-tenant-* namespaces exist in the cluster.
func TestRBACProfileBackfill_NoTenantNamespaces(t *testing.T) {
	c := newBackfillClient(t, backfillNamespace("default"), backfillNamespace("kube-system"))
	r := &controller.RBACProfileBackfillRunnable{Client: c}

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("runOnce returned unexpected error: %v", err)
	}
	// No RBACProfiles should have been created.
	profileList := &securityv1alpha1.RBACProfileList{}
	if err := c.List(context.Background(), profileList); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	if len(profileList.Items) != 0 {
		t.Errorf("expected 0 RBACProfiles; got %d", len(profileList.Items))
	}
}

// TestRBACProfileBackfill_TenantNamespaceWithNoPermissionSets verifies that
// runOnce is a no-op when seam-tenant-* exists but has no PermissionSets.
func TestRBACProfileBackfill_TenantNamespaceWithNoPermissionSets(t *testing.T) {
	c := newBackfillClient(t, backfillNamespace("seam-tenant-prod"))
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

// TestRBACProfileBackfill_PermissionSetWithExistingProfile verifies that runOnce
// does not overwrite or re-create an RBACProfile that already exists.
func TestRBACProfileBackfill_PermissionSetWithExistingProfile(t *testing.T) {
	ns := "seam-tenant-dev"
	c := newBackfillClient(t,
		backfillNamespace(ns),
		backfillPermissionSet("nginx-ingress", ns),
		backfillRBACProfile("nginx-ingress", ns),
	)
	r := &controller.RBACProfileBackfillRunnable{Client: c}

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("runOnce returned unexpected error: %v", err)
	}
	// Profile count should still be exactly 1.
	profileList := &securityv1alpha1.RBACProfileList{}
	if err := c.List(context.Background(), profileList, client.InNamespace(ns)); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	if len(profileList.Items) != 1 {
		t.Errorf("expected 1 RBACProfile after no-op; got %d", len(profileList.Items))
	}
}

// TestRBACProfileBackfill_FillsMissingRBACProfile verifies that when a PermissionSet
// exists in seam-tenant-{cluster} but no RBACProfile exists, runOnce creates it.
// Decision F: targetCluster is derived from the namespace suffix.
func TestRBACProfileBackfill_FillsMissingRBACProfile(t *testing.T) {
	ns := "seam-tenant-ccs-mgmt"
	c := newBackfillClient(t,
		backfillNamespace(ns),
		backfillPermissionSet("cilium", ns),
	)
	r := &controller.RBACProfileBackfillRunnable{Client: c}

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("runOnce returned unexpected error: %v", err)
	}

	// EnsurePackRBACProfileCRs creates RBACProfile via SSA as unstructured.
	// The fake client stores it; we verify presence via the typed lister.
	profile := &securityv1alpha1.RBACProfile{}
	err := c.Get(context.Background(), types.NamespacedName{Name: "cilium", Namespace: ns}, profile)
	if err != nil {
		t.Errorf("RBACProfile not created: %v", err)
	}
}

// TestRBACProfileBackfill_OnlyProcessesTenantNamespaces verifies that namespaces
// not matching the seam-tenant-* prefix are skipped even if they contain PermissionSets.
func TestRBACProfileBackfill_OnlyProcessesTenantNamespaces(t *testing.T) {
	otherNS := "seam-system"
	c := newBackfillClient(t,
		backfillNamespace("seam-tenant-prod"),
		backfillNamespace(otherNS),
		backfillPermissionSet("some-pack", otherNS),
	)
	r := &controller.RBACProfileBackfillRunnable{Client: c}

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("runOnce returned unexpected error: %v", err)
	}
	// No PermissionSets in seam-tenant-prod so no profiles should be created.
	profileList := &securityv1alpha1.RBACProfileList{}
	if err := c.List(context.Background(), profileList); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	if len(profileList.Items) != 0 {
		t.Errorf("expected 0 RBACProfiles; got %d", len(profileList.Items))
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
		backfillPermissionSet("pack-a", ns1),
		backfillPermissionSet("pack-b", ns2),
		// ns2 already has an RBACProfile for pack-b -- should not be re-created.
		backfillRBACProfile("pack-b", ns2),
	)
	r := &controller.RBACProfileBackfillRunnable{Client: c}

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("runOnce returned unexpected error: %v", err)
	}

	// pack-a in ns1 should have been created.
	profileA := &securityv1alpha1.RBACProfile{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "pack-a", Namespace: ns1}, profileA); err != nil {
		t.Errorf("RBACProfile for pack-a not created: %v", err)
	}

	// pack-b in ns2 should still exist (not replaced).
	profileB := &securityv1alpha1.RBACProfile{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "pack-b", Namespace: ns2}, profileB); err != nil {
		t.Errorf("RBACProfile for pack-b missing after no-op: %v", err)
	}
}
