// Package controller_test -- unit tests for APIGroupSweepController.
//
// Verifies:
//   - isSystemGroup correctly classifies k8s, CAPI, seam, and third-party groups.
//   - collectThirdPartyGroups extracts only non-system groups from a CRD list.
//   - explicitGroupsInPermissionSet identifies groups with explicit (non-wildcard) rules.
//   - Reconcile adds explicit rules to management-maximum for new third-party groups.
//   - Reconcile is idempotent -- already-known groups do not produce duplicate rules.
//   - Reconcile requeues when management-maximum is absent.
//   - Guardian.Status.DiscoveredAPIGroups is updated after reconcile.
//   - Reconcile succeeds when the Guardian singleton is absent (status update skipped).
//
// guardian-schema.md §21.
package controller_test

import (
	"context"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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
)

// buildAPIGroupSweepScheme returns a scheme with core, security, and apiextensions types.
func buildAPIGroupSweepScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(securityv1alpha1.AddToScheme(s))
	utilruntime.Must(apiextensionsv1.AddToScheme(s))
	return s
}

// sweepMgmtMax returns a management-maximum PermissionSet with one wildcard rule.
func sweepMgmtMax() *securityv1alpha1.PermissionSet {
	return &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "management-maximum",
			Namespace: "seam-system",
		},
		Spec: securityv1alpha1.PermissionSetSpec{
			Permissions: []securityv1alpha1.PermissionRule{
				{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []securityv1alpha1.Verb{"get", "list", "watch", "create", "update", "patch", "delete"}},
			},
		},
	}
}

// sweepGuardian returns the Guardian singleton CR.
func sweepGuardian() *securityv1alpha1.Guardian {
	return &securityv1alpha1.Guardian{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "guardian",
			Namespace: "seam-system",
		},
	}
}

// makeCRD returns a minimal CRD for the given group.
func makeCRD(name, group string) *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: group,
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:     "Fake",
				Plural:   "fakes",
				Singular: "fake",
			},
			Scope: apiextensionsv1.ClusterScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{Name: "v1alpha1", Served: true, Storage: true},
			},
		},
	}
}

// ---- isSystemGroup unit tests -----------------------------------------------

func TestIsSystemGroup_EmptyGroup(t *testing.T) {
	if !controller.IsSystemGroup("") {
		t.Error("empty string must be classified as system group")
	}
}

func TestIsSystemGroup_K8sBuiltinDotted(t *testing.T) {
	cases := []string{
		"apiextensions.k8s.io",
		"rbac.authorization.k8s.io",
		"networking.k8s.io",
		"storage.k8s.io",
		"admissionregistration.k8s.io",
	}
	for _, g := range cases {
		if !controller.IsSystemGroup(g) {
			t.Errorf("group %q should be classified as system", g)
		}
	}
}

func TestIsSystemGroup_K8sBuiltinBare(t *testing.T) {
	cases := []string{"apps", "batch", "autoscaling", "policy", "core"}
	for _, g := range cases {
		if !controller.IsSystemGroup(g) {
			t.Errorf("bare k8s group %q should be classified as system", g)
		}
	}
}

func TestIsSystemGroup_CAPIGroups(t *testing.T) {
	cases := []string{
		"cluster.x-k8s.io",
		"controlplane.cluster.x-k8s.io",
		"bootstrap.cluster.x-k8s.io",
		"infrastructure.cluster.x-k8s.io",
	}
	for _, g := range cases {
		if !controller.IsSystemGroup(g) {
			t.Errorf("CAPI group %q should be classified as system", g)
		}
	}
}

func TestIsSystemGroup_SeamGroups(t *testing.T) {
	cases := []string{
		"security.ontai.dev",
		"infrastructure.ontai.dev",
		"platform.ontai.dev",
		"core.ontai.dev",
	}
	for _, g := range cases {
		if !controller.IsSystemGroup(g) {
			t.Errorf("seam group %q should be classified as system", g)
		}
	}
}

func TestIsSystemGroup_ThirdPartyGroups(t *testing.T) {
	cases := []string{
		"cert-manager.io",
		"kueue.x-k8s.io", // note: x-k8s.io IS filtered
		"monitoring.coreos.com",
		"postgresql.cnpg.io",
		"argoproj.io",
	}
	// kueue.x-k8s.io should be system (x-k8s.io suffix)
	if !controller.IsSystemGroup("kueue.x-k8s.io") {
		t.Error("kueue.x-k8s.io (x-k8s.io suffix) should be classified as system")
	}
	// Others should be third-party
	thirdParty := []string{"cert-manager.io", "monitoring.coreos.com", "postgresql.cnpg.io", "argoproj.io"}
	for _, g := range thirdParty {
		if controller.IsSystemGroup(g) {
			t.Errorf("group %q should NOT be classified as system", g)
		}
	}
	_ = cases
}

// ---- collectThirdPartyGroups unit tests -------------------------------------

func TestCollectThirdPartyGroups_FiltersSystem(t *testing.T) {
	crds := []apiextensionsv1.CustomResourceDefinition{
		*makeCRD("certs.cert-manager.io", "cert-manager.io"),
		*makeCRD("foos.apps", "apps"),
		*makeCRD("bars.apiextensions.k8s.io", "apiextensions.k8s.io"),
		*makeCRD("clusters.cluster.x-k8s.io", "cluster.x-k8s.io"),
		*makeCRD("pols.security.ontai.dev", "security.ontai.dev"),
	}
	got := controller.CollectThirdPartyGroups(crds)
	if len(got) != 1 {
		t.Fatalf("expected 1 third-party group, got %d: %v", len(got), got)
	}
	if !got["cert-manager.io"] {
		t.Error("cert-manager.io should be in the third-party set")
	}
}

func TestCollectThirdPartyGroups_MultipleThirdParty(t *testing.T) {
	crds := []apiextensionsv1.CustomResourceDefinition{
		*makeCRD("a.cert-manager.io", "cert-manager.io"),
		*makeCRD("b.cert-manager.io", "cert-manager.io"), // duplicate group
		*makeCRD("c.monitoring.coreos.com", "monitoring.coreos.com"),
	}
	got := controller.CollectThirdPartyGroups(crds)
	if len(got) != 2 {
		t.Fatalf("expected 2 third-party groups (deduped), got %d", len(got))
	}
}

// ---- explicitGroupsInPermissionSet unit tests --------------------------------

func TestExplicitGroupsInPermissionSet_WildcardExcluded(t *testing.T) {
	ps := sweepMgmtMax()
	got := controller.ExplicitGroupsInPermissionSet(ps)
	if len(got) != 0 {
		t.Errorf("wildcard-only PermissionSet should have 0 explicit groups; got %v", got)
	}
}

func TestExplicitGroupsInPermissionSet_ExplicitIncluded(t *testing.T) {
	ps := sweepMgmtMax()
	ps.Spec.Permissions = append(ps.Spec.Permissions, securityv1alpha1.PermissionRule{
		APIGroups: []string{"cert-manager.io"},
		Resources: []string{"*"},
		Verbs:     []securityv1alpha1.Verb{"get"},
	})
	got := controller.ExplicitGroupsInPermissionSet(ps)
	if !got["cert-manager.io"] {
		t.Error("cert-manager.io should be in explicit groups")
	}
	if got["*"] {
		t.Error("wildcard should not appear in explicit groups")
	}
}

// ---- Full reconcile tests ---------------------------------------------------

func TestAPIGroupSweep_NewGroupAdded(t *testing.T) {
	scheme := buildAPIGroupSweepScheme(t)
	crd := makeCRD("certs.cert-manager.io", "cert-manager.io")
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sweepMgmtMax(), sweepGuardian(), crd).
		WithStatusSubresource(&securityv1alpha1.Guardian{}, &securityv1alpha1.PermissionSet{}).
		Build()

	r := &controller.APIGroupSweepController{
		Client:            c,
		Scheme:            scheme,
		OperatorNamespace: "seam-system",
	}
	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "sweep/apigroups"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue; got RequeueAfter=%v", result.RequeueAfter)
	}

	// management-maximum should now have an explicit cert-manager.io rule.
	ps := &securityv1alpha1.PermissionSet{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "management-maximum", Namespace: "seam-system"}, ps); err != nil {
		t.Fatalf("get management-maximum: %v", err)
	}
	found := false
	for _, rule := range ps.Spec.Permissions {
		for _, g := range rule.APIGroups {
			if g == "cert-manager.io" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected cert-manager.io rule in management-maximum; not found")
	}

	// Guardian status should list the discovered group.
	gdn := &securityv1alpha1.Guardian{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "guardian", Namespace: "seam-system"}, gdn); err != nil {
		t.Fatalf("get Guardian: %v", err)
	}
	if len(gdn.Status.DiscoveredAPIGroups) != 1 || gdn.Status.DiscoveredAPIGroups[0] != "cert-manager.io" {
		t.Errorf("DiscoveredAPIGroups = %v; want [cert-manager.io]", gdn.Status.DiscoveredAPIGroups)
	}
}

func TestAPIGroupSweep_Idempotent(t *testing.T) {
	scheme := buildAPIGroupSweepScheme(t)
	ps := sweepMgmtMax()
	// Pre-seed an existing explicit rule for cert-manager.io.
	ps.Spec.Permissions = append(ps.Spec.Permissions, securityv1alpha1.PermissionRule{
		APIGroups: []string{"cert-manager.io"},
		Resources: []string{"*"},
		Verbs:     []securityv1alpha1.Verb{"get", "list", "watch", "create", "update", "patch", "delete"},
	})
	crd := makeCRD("certs.cert-manager.io", "cert-manager.io")
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ps, sweepGuardian(), crd).
		WithStatusSubresource(&securityv1alpha1.Guardian{}, &securityv1alpha1.PermissionSet{}).
		Build()

	r := &controller.APIGroupSweepController{
		Client:            c,
		Scheme:            scheme,
		OperatorNamespace: "seam-system",
	}
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "sweep/apigroups"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// Must not have created a second cert-manager.io rule.
	got := &securityv1alpha1.PermissionSet{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "management-maximum", Namespace: "seam-system"}, got); err != nil {
		t.Fatalf("get management-maximum: %v", err)
	}
	count := 0
	for _, rule := range got.Spec.Permissions {
		for _, g := range rule.APIGroups {
			if g == "cert-manager.io" {
				count++
			}
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 cert-manager.io rule; got %d", count)
	}
}

func TestAPIGroupSweep_ManagementMaximumAbsent_Requeues(t *testing.T) {
	scheme := buildAPIGroupSweepScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	r := &controller.APIGroupSweepController{
		Client:            c,
		Scheme:            scheme,
		OperatorNamespace: "seam-system",
	}
	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "sweep/apigroups"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("expected RequeueAfter > 0 when management-maximum is absent")
	}
}

func TestAPIGroupSweep_GuardianAbsent_NoError(t *testing.T) {
	scheme := buildAPIGroupSweepScheme(t)
	crd := makeCRD("certs.cert-manager.io", "cert-manager.io")
	// No Guardian CR in the fake client.
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sweepMgmtMax(), crd).
		WithStatusSubresource(&securityv1alpha1.PermissionSet{}).
		Build()

	r := &controller.APIGroupSweepController{
		Client:            c,
		Scheme:            scheme,
		OperatorNamespace: "seam-system",
	}
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "sweep/apigroups"},
	})
	if err != nil {
		t.Errorf("expected no error when Guardian singleton absent; got: %v", err)
	}
}

func TestAPIGroupSweep_NonSweepKey_Ignored(t *testing.T) {
	scheme := buildAPIGroupSweepScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &controller.APIGroupSweepController{
		Client:            c,
		Scheme:            scheme,
		OperatorNamespace: "seam-system",
	}
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "something-else"},
	})
	if err != nil {
		t.Errorf("unexpected error for non-sweep key: %v", err)
	}
}

func TestAPIGroupSweep_SystemGroupsNotAdded(t *testing.T) {
	scheme := buildAPIGroupSweepScheme(t)
	crds := []apiextensionsv1.CustomResourceDefinition{
		*makeCRD("foos.apps", "apps"),
		*makeCRD("bars.rbac.authorization.k8s.io", "rbac.authorization.k8s.io"),
		*makeCRD("clusters.cluster.x-k8s.io", "cluster.x-k8s.io"),
		*makeCRD("pols.security.ontai.dev", "security.ontai.dev"),
	}
	clientObjs := []client.Object{sweepMgmtMax(), sweepGuardian()}
	for i := range crds {
		clientObjs = append(clientObjs, &crds[i])
	}
	cAny := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clientObjs...).
		WithStatusSubresource(&securityv1alpha1.Guardian{}, &securityv1alpha1.PermissionSet{}).
		Build()

	r := &controller.APIGroupSweepController{
		Client:            cAny,
		Scheme:            scheme,
		OperatorNamespace: "seam-system",
	}
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "sweep/apigroups"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := &securityv1alpha1.PermissionSet{}
	if err := cAny.Get(context.Background(), types.NamespacedName{Name: "management-maximum", Namespace: "seam-system"}, got); err != nil {
		t.Fatalf("get management-maximum: %v", err)
	}
	// Only the original wildcard rule should be present.
	if len(got.Spec.Permissions) != 1 {
		t.Errorf("expected 1 rule (wildcard only); got %d rules", len(got.Spec.Permissions))
	}

	gdn := &securityv1alpha1.Guardian{}
	if err := cAny.Get(context.Background(), types.NamespacedName{Name: "guardian", Namespace: "seam-system"}, gdn); err != nil {
		t.Fatalf("get Guardian: %v", err)
	}
	if len(gdn.Status.DiscoveredAPIGroups) != 0 {
		t.Errorf("DiscoveredAPIGroups should be empty; got %v", gdn.Status.DiscoveredAPIGroups)
	}
}
