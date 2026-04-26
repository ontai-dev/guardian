// Package controller_test contains unit tests for RBACProfileReconciler
// PermissionSet watch mapping (GUARDIAN-BL-PERMISSIONSET-WATCH).
//
// Tests cover:
//   - PermissionSet update enqueues all RBACProfiles referencing it.
//   - PermissionSet update for an unreferenced PermissionSet enqueues nothing.
//   - Reconciler produces correct ClusterRole rules after PermissionSet content changes.
//
// The mapping function (MapPermissionSetToProfiles) is tested directly using a fake
// client pre-populated with RBACProfiles. Integration with SetupWithManager is
// architectural — the controller-runtime builder wires the function as the handler.
package controller_test

import (
	"context"
	"sort"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	clientevents "k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildWatchScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(securityv1alpha1.AddToScheme(s))
	return s
}

func buildWatchReconciler(t *testing.T, objs ...client.Object) *controller.RBACProfileReconciler {
	t.Helper()
	s := buildWatchScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&securityv1alpha1.RBACProfile{}).
		Build()
	return &controller.RBACProfileReconciler{
		Client:   c,
		Scheme:   s,
		Recorder: clientevents.NewFakeRecorder(32),
	}
}

func makeProfile(name, ns string, psRefs ...string) *securityv1alpha1.RBACProfile {
	decls := make([]securityv1alpha1.PermissionDeclaration, len(psRefs))
	for i, ref := range psRefs {
		decls[i] = securityv1alpha1.PermissionDeclaration{
			PermissionSetRef: ref,
			Scope:            securityv1alpha1.PermissionScopeCluster,
		}
	}
	return &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Generation: 1},
		Spec: securityv1alpha1.RBACProfileSpec{
			PrincipalRef:           "system:serviceaccount:" + ns + ":" + name + "-sa",
			RBACPolicyRef:          "management-policy",
			TargetClusters:         []string{"ccs-test"},
			PermissionDeclarations: decls,
		},
	}
}

func makePS(name, ns string, rules ...securityv1alpha1.PermissionRule) *securityv1alpha1.PermissionSet {
	return &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       securityv1alpha1.PermissionSetSpec{Permissions: rules},
	}
}

func podRule() securityv1alpha1.PermissionRule {
	return securityv1alpha1.PermissionRule{
		APIGroups: []string{""},
		Resources: []string{"pods"},
		Verbs:     []securityv1alpha1.Verb{"get", "list"},
	}
}

func secretRule() securityv1alpha1.PermissionRule {
	return securityv1alpha1.PermissionRule{
		APIGroups: []string{""},
		Resources: []string{"secrets"},
		Verbs:     []securityv1alpha1.Verb{"get"},
	}
}

// requestNames returns the sorted list of profile names from reconcile requests.
func requestNames(reqs []reconcile.Request) []string {
	names := make([]string, len(reqs))
	for i, r := range reqs {
		names[i] = r.Name
	}
	sort.Strings(names)
	return names
}

// ---------------------------------------------------------------------------
// Mapping function tests
// ---------------------------------------------------------------------------

// TestMapPermissionSetToProfiles_EnqueuesReferencingProfiles verifies that when a
// PermissionSet changes, all RBACProfiles in the same namespace that reference it
// via permissionDeclarations.permissionSetRef are enqueued.
func TestMapPermissionSetToProfiles_EnqueuesReferencingProfiles(t *testing.T) {
	ns := "seam-system"
	ps := makePS("management-maximum", ns, podRule())

	// Two profiles reference management-maximum; one does not.
	profileA := makeProfile("guardian-profile", ns, "management-maximum")
	profileB := makeProfile("conductor-profile", ns, "management-maximum")
	profileC := makeProfile("other-profile", ns, "some-other-ps")

	r := buildWatchReconciler(t, ps, profileA, profileB, profileC)

	reqs := r.MapPermissionSetToProfiles(context.Background(), ps)
	if len(reqs) != 2 {
		t.Fatalf("expected 2 reconcile requests, got %d", len(reqs))
	}
	got := requestNames(reqs)
	if got[0] != "conductor-profile" || got[1] != "guardian-profile" {
		t.Errorf("unexpected request names: %v", got)
	}
}

// TestMapPermissionSetToProfiles_UnreferencedPermissionSetEnqueuesNothing verifies
// that when a PermissionSet changes and no RBACProfile references it, no reconcile
// requests are produced.
func TestMapPermissionSetToProfiles_UnreferencedPermissionSetEnqueuesNothing(t *testing.T) {
	ns := "seam-system"
	ps := makePS("unused-ps", ns, podRule())

	// Both profiles reference a different PermissionSet.
	profileA := makeProfile("guardian-profile", ns, "management-maximum")
	profileB := makeProfile("conductor-profile", ns, "management-maximum")

	r := buildWatchReconciler(t, ps, profileA, profileB)

	reqs := r.MapPermissionSetToProfiles(context.Background(), ps)
	if len(reqs) != 0 {
		t.Fatalf("expected 0 reconcile requests for unreferenced PermissionSet, got %d: %v", len(reqs), reqs)
	}
}

// TestMapPermissionSetToProfiles_CrossNamespaceIsolation verifies that only profiles
// in the SAME namespace as the changed PermissionSet are enqueued. Profiles in other
// namespaces that happen to have a permissionSetRef with the same name are not touched.
func TestMapPermissionSetToProfiles_CrossNamespaceIsolation(t *testing.T) {
	ns1 := "seam-system"
	ns2 := "seam-tenant-other"
	ps := makePS("management-maximum", ns1, podRule())

	profileInNS1 := makeProfile("guardian-profile", ns1, "management-maximum")
	profileInNS2 := makeProfile("other-profile", ns2, "management-maximum")

	r := buildWatchReconciler(t, ps, profileInNS1, profileInNS2)

	reqs := r.MapPermissionSetToProfiles(context.Background(), ps)
	if len(reqs) != 1 {
		t.Fatalf("expected 1 reconcile request (same namespace only), got %d", len(reqs))
	}
	if reqs[0].Name != "guardian-profile" || reqs[0].Namespace != ns1 {
		t.Errorf("unexpected request: %v", reqs[0])
	}
}

// TestMapPermissionSetToProfiles_ProfileWithMultipleDeclarationsEnqueuedOnce verifies
// that a profile referencing the same PermissionSet in multiple declarations is only
// enqueued once (break after first match).
func TestMapPermissionSetToProfiles_ProfileWithMultipleDeclarationsEnqueuedOnce(t *testing.T) {
	ns := "seam-system"
	ps := makePS("management-maximum", ns, podRule())
	// Profile references management-maximum twice (unusual but possible).
	profile := makeProfile("conductor-profile", ns, "management-maximum", "management-maximum")

	r := buildWatchReconciler(t, ps, profile)

	reqs := r.MapPermissionSetToProfiles(context.Background(), ps)
	if len(reqs) != 1 {
		t.Fatalf("expected 1 reconcile request (not duplicated), got %d", len(reqs))
	}
}

// ---------------------------------------------------------------------------
// ClusterRole content after PermissionSet change
// ---------------------------------------------------------------------------

// TestReconciler_ClusterRoleUpdatedAfterPermissionSetChange verifies that after a
// PermissionSet's rules change and the referencing RBACProfile is reconciled, the
// resulting ClusterRole reflects the new rules. This confirms that the reconciler
// correctly re-reads the PermissionSet on every reconcile cycle.
func TestReconciler_ClusterRoleUpdatedAfterPermissionSetChange(t *testing.T) {
	ns := "seam-system"
	policy := makePolicyForProvisioning("management-policy", ns)
	ps := makePS("management-maximum", ns, podRule())
	profile := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "conductor-profile", Namespace: ns, Generation: 1},
		Spec: securityv1alpha1.RBACProfileSpec{
			PrincipalRef:   "system:serviceaccount:ont-system:conductor",
			RBACPolicyRef:  policy.Name,
			TargetClusters: []string{"ccs-test"},
			PermissionDeclarations: []securityv1alpha1.PermissionDeclaration{
				{PermissionSetRef: ps.Name, Scope: securityv1alpha1.PermissionScopeCluster},
			},
		},
	}

	s := buildWatchScheme(t)
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(policy, ps, profile).
		WithStatusSubresource(&securityv1alpha1.RBACProfile{}).
		Build()
	r := &controller.RBACProfileReconciler{
		Client:   fakeClient,
		Scheme:   s,
		Recorder: clientevents.NewFakeRecorder(32),
	}

	// First reconcile: PermissionSet has pod rule only.
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: profile.Name, Namespace: ns},
	}); err != nil {
		t.Fatalf("first reconcile error: %v", err)
	}

	cr := &rbacv1.ClusterRole{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "seam:conductor"}, cr); err != nil {
		t.Fatalf("ClusterRole not found after first reconcile: %v", err)
	}
	if len(cr.Rules) != 1 || cr.Rules[0].Resources[0] != "pods" {
		t.Errorf("expected ClusterRole with pod rule after first reconcile, got: %v", cr.Rules)
	}

	// Simulate PermissionSet content change: now includes secrets rule.
	updatedPS := makePS("management-maximum", ns, podRule(), secretRule())
	updatedPS.ResourceVersion = ps.ResourceVersion
	if err := fakeClient.Update(context.Background(), updatedPS); err != nil {
		t.Fatalf("failed to update PermissionSet: %v", err)
	}

	// Force the ObservedGeneration guard to allow re-processing by bumping Generation.
	profileFetched := &securityv1alpha1.RBACProfile{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: profile.Name, Namespace: ns}, profileFetched); err != nil {
		t.Fatalf("failed to get profile: %v", err)
	}
	profileFetched.Generation = 2
	if err := fakeClient.Update(context.Background(), profileFetched); err != nil {
		t.Fatalf("failed to update profile generation: %v", err)
	}

	// Second reconcile: triggered by PermissionSet change (simulated by enqueue).
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: profile.Name, Namespace: ns},
	}); err != nil {
		t.Fatalf("second reconcile error: %v", err)
	}

	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "seam:conductor"}, cr); err != nil {
		t.Fatalf("ClusterRole not found after second reconcile: %v", err)
	}
	resources := make(map[string]bool)
	for _, rule := range cr.Rules {
		for _, res := range rule.Resources {
			resources[res] = true
		}
	}
	if !resources["pods"] || !resources["secrets"] {
		t.Errorf("expected ClusterRole to contain both pods and secrets rules after PermissionSet update, got: %v", cr.Rules)
	}
}
