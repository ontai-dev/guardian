// Package controller_test -- unit tests for ClusterRBACPolicyReconciler.
//
// Tests verify the three-layer RBAC hierarchy provisioning contract:
//   - On TalosCluster creation: cluster-maximum PermissionSet + cluster-policy RBACPolicy
//     created in seam-tenant-{clusterName}, inheriting permissions from management-maximum.
//   - Finalizer security.ontai.dev/cluster-rbac is added to TalosCluster.
//   - Second reconcile is idempotent (no duplicate objects, no error).
//   - On TalosCluster deletion: all component-labeled RBACProfiles deleted, then
//     cluster objects deleted, then finalizer removed.
//   - cluster-maximum permissions are copied from management-maximum (Layer 1 obligation).
//   - When management-maximum changes, cluster-maximum is updated to match (re-sync path).
//   - enqueueAllTalosClusters returns a request for every TalosCluster (fanout for
//     management-maximum change events). guardian-schema.md §18.
//
// guardian-schema.md §18, §19, CS-INV-008, CS-INV-009.
package controller_test

import (
	"context"
	"testing"

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

// buildClusterRBACScheme returns a scheme with core, security, and seam-core types.
func buildClusterRBACScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(securityv1alpha1.AddToScheme(s))
	utilruntime.Must(seamv1alpha1.AddToScheme(s))
	return s
}

// managementMaximumPermSet returns the compiler-created Layer 1 PermissionSet.
// guardian-schema.md §19 Layer 1.
func managementMaximumPermSet() *securityv1alpha1.PermissionSet {
	return &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "management-maximum",
			Namespace: "seam-system",
		},
		Spec: securityv1alpha1.PermissionSetSpec{
			Description: "Fleet ceiling",
			Permissions: []securityv1alpha1.PermissionRule{
				{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []securityv1alpha1.Verb{"get", "list", "watch"}},
			},
		},
	}
}

// newTalosCluster returns a minimal InfrastructureTalosCluster in seam-system.
func newTalosClusterForRBACTest(name string) *seamv1alpha1.InfrastructureTalosCluster {
	return &seamv1alpha1.InfrastructureTalosCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "seam-system",
		},
	}
}

// buildClusterRBACClient builds a fake client pre-seeded with management-maximum
// (Layer 1 PermissionSet, compiler-created) and any additional objects.
func buildClusterRBACClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	all := []client.Object{managementMaximumPermSet()}
	all = append(all, objs...)
	return fake.NewClientBuilder().
		WithScheme(buildClusterRBACScheme(t)).
		WithObjects(all...).
		WithStatusSubresource(&seamv1alpha1.InfrastructureTalosCluster{}).
		Build()
}

// reconcileClusterRBAC runs one reconcile for the given TalosCluster.
func reconcileClusterRBAC(t *testing.T, r *controller.ClusterRBACPolicyReconciler, name string) ctrl.Result {
	t.Helper()
	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: name, Namespace: "seam-system"},
	})
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}
	return result
}

// TestClusterRBACPolicyReconciler_CreatesClusterObjects verifies that reconciling a
// new TalosCluster creates cluster-maximum PermissionSet and cluster-policy RBACPolicy
// in seam-tenant-{clusterName}. guardian-schema.md §18, §19 Layer 2.
func TestClusterRBACPolicyReconciler_CreatesClusterObjects(t *testing.T) {
	tc := newTalosClusterForRBACTest("ccs-mgmt")
	c := buildClusterRBACClient(t, tc)
	r := &controller.ClusterRBACPolicyReconciler{Client: c, Scheme: buildClusterRBACScheme(t)}

	reconcileClusterRBAC(t, r, "ccs-mgmt")

	ns := "seam-tenant-ccs-mgmt"

	// cluster-maximum PermissionSet must exist.
	ps := &securityv1alpha1.PermissionSet{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: "cluster-maximum", Namespace: ns,
	}, ps); err != nil {
		t.Fatalf("cluster-maximum PermissionSet not created: %v", err)
	}
	if ps.GetLabels()["ontai.dev/policy-type"] != "cluster" {
		t.Errorf("policy-type label: got %q want cluster", ps.GetLabels()["ontai.dev/policy-type"])
	}

	// cluster-policy RBACPolicy must exist.
	policy := &securityv1alpha1.RBACPolicy{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: "cluster-policy", Namespace: ns,
	}, policy); err != nil {
		t.Fatalf("cluster-policy RBACPolicy not created: %v", err)
	}
	if policy.Spec.MaximumPermissionSetRef != "cluster-maximum" {
		t.Errorf("maximumPermissionSetRef: got %q want cluster-maximum", policy.Spec.MaximumPermissionSetRef)
	}
	if policy.Spec.SubjectScope != "tenant" {
		t.Errorf("subjectScope: got %q want tenant", policy.Spec.SubjectScope)
	}
	if len(policy.Spec.AllowedClusters) != 1 || policy.Spec.AllowedClusters[0] != "ccs-mgmt" {
		t.Errorf("allowedClusters: got %v want [ccs-mgmt]", policy.Spec.AllowedClusters)
	}
}

// TestClusterRBACPolicyReconciler_AddsFinalizer verifies that the finalizer
// security.ontai.dev/cluster-rbac is added to the TalosCluster. guardian-schema.md §18.
func TestClusterRBACPolicyReconciler_AddsFinalizer(t *testing.T) {
	tc := newTalosClusterForRBACTest("prod")
	c := buildClusterRBACClient(t, tc)
	r := &controller.ClusterRBACPolicyReconciler{Client: c, Scheme: buildClusterRBACScheme(t)}

	reconcileClusterRBAC(t, r, "prod")

	updated := &seamv1alpha1.InfrastructureTalosCluster{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: "prod", Namespace: "seam-system",
	}, updated); err != nil {
		t.Fatalf("get TalosCluster: %v", err)
	}
	found := false
	for _, f := range updated.Finalizers {
		if f == "security.ontai.dev/cluster-rbac" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("finalizer security.ontai.dev/cluster-rbac not found on TalosCluster, got: %v", updated.Finalizers)
	}
}

// TestClusterRBACPolicyReconciler_Idempotent verifies that a second reconcile does
// not create duplicate objects and does not error. guardian-schema.md §18.
func TestClusterRBACPolicyReconciler_Idempotent(t *testing.T) {
	tc := newTalosClusterForRBACTest("staging")
	c := buildClusterRBACClient(t, tc)
	r := &controller.ClusterRBACPolicyReconciler{Client: c, Scheme: buildClusterRBACScheme(t)}

	reconcileClusterRBAC(t, r, "staging")
	reconcileClusterRBAC(t, r, "staging")

	ns := "seam-tenant-staging"

	psList := &securityv1alpha1.PermissionSetList{}
	if err := c.List(context.Background(), psList, client.InNamespace(ns)); err != nil {
		t.Fatalf("list PermissionSets: %v", err)
	}
	if len(psList.Items) != 1 {
		t.Errorf("expected exactly 1 PermissionSet after idempotent reconcile; got %d", len(psList.Items))
	}

	policyList := &securityv1alpha1.RBACPolicyList{}
	if err := c.List(context.Background(), policyList, client.InNamespace(ns)); err != nil {
		t.Fatalf("list RBACPolicies: %v", err)
	}
	if len(policyList.Items) != 1 {
		t.Errorf("expected exactly 1 RBACPolicy after idempotent reconcile; got %d", len(policyList.Items))
	}
}

// TestClusterRBACPolicyReconciler_ClusterMaximumInheritsFromManagementMaximum verifies
// that the cluster-maximum permissions are copied from management-maximum, fulfilling
// the functional obligation of Layer 2 to Layer 1. guardian-schema.md §19, CS-INV-009.
func TestClusterRBACPolicyReconciler_ClusterMaximumInheritsFromManagementMaximum(t *testing.T) {
	tc := newTalosClusterForRBACTest("dev")
	c := buildClusterRBACClient(t, tc)
	r := &controller.ClusterRBACPolicyReconciler{Client: c, Scheme: buildClusterRBACScheme(t)}

	reconcileClusterRBAC(t, r, "dev")

	mgmtMax := managementMaximumPermSet()
	clusterMax := &securityv1alpha1.PermissionSet{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: "cluster-maximum", Namespace: "seam-tenant-dev",
	}, clusterMax); err != nil {
		t.Fatalf("cluster-maximum not found: %v", err)
	}

	if len(clusterMax.Spec.Permissions) != len(mgmtMax.Spec.Permissions) {
		t.Errorf("cluster-maximum permission count %d != management-maximum %d",
			len(clusterMax.Spec.Permissions), len(mgmtMax.Spec.Permissions))
	}
}

// TestClusterRBACPolicyReconciler_DeleteCascadesComponentProfiles verifies the deletion
// cascade: all component-labeled RBACProfiles deleted, then cluster objects, then
// finalizer removed. guardian-schema.md §18 deletion cascade.
func TestClusterRBACPolicyReconciler_DeleteCascadesComponentProfiles(t *testing.T) {
	now := metav1.Now()
	tc := &seamv1alpha1.InfrastructureTalosCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "ccs-dev",
			Namespace:         "seam-system",
			DeletionTimestamp: &now,
			Finalizers:        []string{"security.ontai.dev/cluster-rbac"},
		},
	}

	ns := "seam-tenant-ccs-dev"
	// Pre-create cluster objects and two component RBACProfiles.
	clusterPS := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-maximum", Namespace: ns,
			Labels: map[string]string{"ontai.dev/policy-type": "cluster"}},
	}
	clusterPolicy := &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-policy", Namespace: ns,
			Labels: map[string]string{"ontai.dev/policy-type": "cluster"}},
	}
	profileA := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cert-manager", Namespace: ns,
			Labels: map[string]string{"ontai.dev/policy-type": "component"}},
	}
	profileB := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium", Namespace: ns,
			Labels: map[string]string{"ontai.dev/policy-type": "component"}},
	}

	c := buildClusterRBACClient(t, tc, clusterPS, clusterPolicy, profileA, profileB)
	r := &controller.ClusterRBACPolicyReconciler{Client: c, Scheme: buildClusterRBACScheme(t)}

	// Must not error.
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "ccs-dev", Namespace: "seam-system"},
	}); err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	// All component profiles must be deleted.
	profileList := &securityv1alpha1.RBACProfileList{}
	if err := c.List(context.Background(), profileList,
		client.InNamespace(ns),
		client.MatchingLabels{"ontai.dev/policy-type": "component"},
	); err != nil {
		t.Fatalf("list component profiles: %v", err)
	}
	if len(profileList.Items) != 0 {
		t.Errorf("expected 0 component RBACProfiles after cascade delete; got %d", len(profileList.Items))
	}

	// cluster-maximum must be deleted.
	remainPS := &securityv1alpha1.PermissionSet{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "cluster-maximum", Namespace: ns}, remainPS); err == nil {
		t.Error("cluster-maximum PermissionSet must be deleted on TalosCluster deletion")
	}

	// cluster-policy must be deleted.
	remainPolicy := &securityv1alpha1.RBACPolicy{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "cluster-policy", Namespace: ns}, remainPolicy); err == nil {
		t.Error("cluster-policy RBACPolicy must be deleted on TalosCluster deletion")
	}

	// Finalizer removal: the fake client deletes the TalosCluster once all finalizers
	// are removed and DeletionTimestamp is set. Verify the object is no longer found,
	// which confirms the finalizer was removed successfully.
	gone := &seamv1alpha1.InfrastructureTalosCluster{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: "ccs-dev", Namespace: "seam-system",
	}, gone); err == nil {
		// Object still exists -- check that our finalizer was removed.
		for _, f := range gone.Finalizers {
			if f == "security.ontai.dev/cluster-rbac" {
				t.Error("cluster-rbac finalizer must be removed after cascade delete completes")
			}
		}
	}
	// If IsNotFound: the object was garbage-collected by the fake client after
	// the last finalizer was removed. This is the expected happy path.
}

// TestClusterRBACPolicyReconciler_SyncsClusterMaximumWhenManagementMaximumChanges
// verifies the re-validation path: if management-maximum permissions change after
// cluster-maximum was already provisioned, the next reconcile updates cluster-maximum
// to match the new fleet ceiling. guardian-schema.md §18.
func TestClusterRBACPolicyReconciler_SyncsClusterMaximumWhenManagementMaximumChanges(t *testing.T) {
	tc := newTalosClusterForRBACTest("resync")
	c := buildClusterRBACClient(t, tc)
	r := &controller.ClusterRBACPolicyReconciler{Client: c, Scheme: buildClusterRBACScheme(t)}

	// First reconcile: cluster-maximum is created with the original management-maximum.
	reconcileClusterRBAC(t, r, "resync")

	ns := "seam-tenant-resync"
	clusterMax := &securityv1alpha1.PermissionSet{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: "cluster-maximum", Namespace: ns,
	}, clusterMax); err != nil {
		t.Fatalf("cluster-maximum not found after first reconcile: %v", err)
	}
	if len(clusterMax.Spec.Permissions) != 1 {
		t.Fatalf("expected 1 permission rule initially; got %d", len(clusterMax.Spec.Permissions))
	}

	// Simulate management-maximum being tightened: add a second rule.
	mgmtMax := &securityv1alpha1.PermissionSet{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: "management-maximum", Namespace: "seam-system",
	}, mgmtMax); err != nil {
		t.Fatalf("get management-maximum: %v", err)
	}
	updatedMgmt := mgmtMax.DeepCopy()
	updatedMgmt.Spec.Permissions = append(updatedMgmt.Spec.Permissions, securityv1alpha1.PermissionRule{
		APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []securityv1alpha1.Verb{"get"},
	})
	if err := c.Update(context.Background(), updatedMgmt); err != nil {
		t.Fatalf("update management-maximum: %v", err)
	}

	// Second reconcile: cluster-maximum must be updated to match the new management-maximum.
	reconcileClusterRBAC(t, r, "resync")

	syncedMax := &securityv1alpha1.PermissionSet{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: "cluster-maximum", Namespace: ns,
	}, syncedMax); err != nil {
		t.Fatalf("cluster-maximum not found after re-sync reconcile: %v", err)
	}
	if len(syncedMax.Spec.Permissions) != 2 {
		t.Errorf("cluster-maximum permissions after re-sync: got %d rules, want 2",
			len(syncedMax.Spec.Permissions))
	}
}

// TestClusterRBACPolicyReconciler_EnqueueAllTalosClusters verifies that the fanout
// function returns one reconcile request per InfrastructureTalosCluster in seam-system.
// This is the function called when management-maximum changes. guardian-schema.md §18.
func TestClusterRBACPolicyReconciler_EnqueueAllTalosClusters(t *testing.T) {
	tc1 := newTalosClusterForRBACTest("alpha")
	tc2 := newTalosClusterForRBACTest("beta")
	c := buildClusterRBACClient(t, tc1, tc2)
	r := &controller.ClusterRBACPolicyReconciler{Client: c, Scheme: buildClusterRBACScheme(t)}

	// Simulate the enqueue triggered by a management-maximum change.
	reqs := r.EnqueueAllTalosClusters(context.Background(), managementMaximumPermSet())

	if len(reqs) != 2 {
		t.Fatalf("expected 2 reconcile requests (one per TalosCluster); got %d", len(reqs))
	}
	names := map[string]bool{}
	for _, req := range reqs {
		names[req.Name] = true
	}
	if !names["alpha"] {
		t.Error("expected request for TalosCluster alpha")
	}
	if !names["beta"] {
		t.Error("expected request for TalosCluster beta")
	}
}

// newTenantTalosCluster returns a minimal InfrastructureTalosCluster with role=tenant.
func newTenantTalosCluster(name string) *seamv1alpha1.InfrastructureTalosCluster {
	return &seamv1alpha1.InfrastructureTalosCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "seam-system",
		},
		Spec: seamv1alpha1.InfrastructureTalosClusterSpec{
			Role: seamv1alpha1.InfrastructureTalosClusterRoleTenant,
		},
	}
}

// TestClusterRBACPolicyReconciler_TenantCluster_CreatesConductorTenantProfile verifies
// that reconciling a role=tenant TalosCluster creates the conductor-tenant RBACProfile
// in seam-tenant-{clusterName}. guardian-schema.md §20 T-19a.
func TestClusterRBACPolicyReconciler_TenantCluster_CreatesConductorTenantProfile(t *testing.T) {
	tc := newTenantTalosCluster("ccs-dev")
	c := buildClusterRBACClient(t, tc)
	r := &controller.ClusterRBACPolicyReconciler{Client: c, Scheme: buildClusterRBACScheme(t)}

	reconcileClusterRBAC(t, r, "ccs-dev")

	ns := "seam-tenant-ccs-dev"
	profile := &securityv1alpha1.RBACProfile{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: "conductor-tenant", Namespace: ns,
	}, profile); err != nil {
		t.Fatalf("conductor-tenant RBACProfile not created in %s: %v", ns, err)
	}
	if profile.Spec.PrincipalRef != "conductor" {
		t.Errorf("principalRef: got %q want conductor", profile.Spec.PrincipalRef)
	}
	if profile.Spec.RBACPolicyRef != "cluster-policy" {
		t.Errorf("rbacPolicyRef: got %q want cluster-policy", profile.Spec.RBACPolicyRef)
	}
	if len(profile.Spec.TargetClusters) != 1 || profile.Spec.TargetClusters[0] != "ccs-dev" {
		t.Errorf("targetClusters: got %v want [ccs-dev]", profile.Spec.TargetClusters)
	}
	if profile.GetLabels()["ontai.dev/policy-type"] != "seam-operator" {
		t.Errorf("policy-type label: got %q want seam-operator", profile.GetLabels()["ontai.dev/policy-type"])
	}
	if len(profile.Spec.PermissionDeclarations) != 1 ||
		profile.Spec.PermissionDeclarations[0].PermissionSetRef != "cluster-maximum" {
		t.Errorf("permissionDeclarations: got %v want [{cluster-maximum cluster}]", profile.Spec.PermissionDeclarations)
	}
}

// TestClusterRBACPolicyReconciler_NonTenantCluster_NoConductorTenantProfile verifies
// that reconciling a cluster without role=tenant does NOT create a conductor-tenant
// RBACProfile. guardian-schema.md §20.
func TestClusterRBACPolicyReconciler_NonTenantCluster_NoConductorTenantProfile(t *testing.T) {
	tc := newTalosClusterForRBACTest("ccs-mgmt") // no role set -- management path
	c := buildClusterRBACClient(t, tc)
	r := &controller.ClusterRBACPolicyReconciler{Client: c, Scheme: buildClusterRBACScheme(t)}

	reconcileClusterRBAC(t, r, "ccs-mgmt")

	ns := "seam-tenant-ccs-mgmt"
	profile := &securityv1alpha1.RBACProfile{}
	err := c.Get(context.Background(), types.NamespacedName{
		Name: "conductor-tenant", Namespace: ns,
	}, profile)
	if err == nil {
		t.Error("conductor-tenant RBACProfile must not be created for non-tenant clusters")
	}
}

// TestClusterRBACPolicyReconciler_TenantDeletion_DeletesConductorTenantProfile verifies
// that the reconcileDelete path removes the conductor-tenant RBACProfile from
// seam-tenant-{clusterName} when the TalosCluster is deleted. guardian-schema.md §20.
func TestClusterRBACPolicyReconciler_TenantDeletion_DeletesConductorTenantProfile(t *testing.T) {
	tc := newTenantTalosCluster("ccs-dev-del")
	now := metav1.Now()
	tc.DeletionTimestamp = &now
	tc.Finalizers = []string{"security.ontai.dev/cluster-rbac"}

	ns := "seam-tenant-ccs-dev-del"

	// Pre-seed: cluster objects and conductor-tenant profile already exist.
	ps := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-maximum", Namespace: ns},
	}
	policy := &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-policy", Namespace: ns},
	}
	conductorProfile := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "conductor-tenant",
			Namespace: ns,
			Labels: map[string]string{
				"ontai.dev/managed-by":  "guardian",
				"ontai.dev/policy-type": "seam-operator",
			},
		},
	}

	c := buildClusterRBACClient(t, tc, ps, policy, conductorProfile)
	r := &controller.ClusterRBACPolicyReconciler{Client: c, Scheme: buildClusterRBACScheme(t)}

	reconcileClusterRBAC(t, r, "ccs-dev-del")

	// conductor-tenant RBACProfile must be gone.
	deleted := &securityv1alpha1.RBACProfile{}
	err := c.Get(context.Background(), types.NamespacedName{
		Name: "conductor-tenant", Namespace: ns,
	}, deleted)
	if err == nil {
		t.Error("conductor-tenant RBACProfile must be deleted when TalosCluster is deleted")
	}
}
