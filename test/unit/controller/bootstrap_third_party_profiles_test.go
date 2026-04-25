package controller_test

// Tests for BootstrapAnnotationRunnable.createThirdPartyProfiles.
//
// Under the three-layer RBAC hierarchy (guardian-schema.md §19):
//   - Only RBACProfile is created per component; no PermissionSet, no RBACPolicy.
//   - Profiles land in seam-tenant-{ManagementClusterName}, not the component namespace.
//   - RBACProfile.Spec.RBACPolicyRef = "cluster-policy" (Layer 2). CS-INV-008.
//   - Component namespace is discovered at runtime via ServiceAccountName. CS-INV-007.
//   - NamespaceHint is used as a tiebreaker on SA name collisions.
//   - PrincipalRef reflects the discovered namespace.
//   - Second run is idempotent: no duplicates, no errors.
//
// guardian-schema.md §3 Step 2, §6, §19, CS-INV-008.

import (
	"context"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
)

// buildSA constructs a ServiceAccount with the given name and namespace.
func buildSA(name, ns string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
	}
}

// newThirdPartyRunnable constructs a BootstrapAnnotationRunnable for third-party profile
// tests with the given cluster name and fake client.
func newThirdPartyRunnable(cl client.Client, clusterName string) *controller.BootstrapAnnotationRunnable {
	return &controller.BootstrapAnnotationRunnable{
		Client:                cl,
		SweepDone:             &atomic.Bool{},
		ManagementClusterName: clusterName,
	}
}

// TestThirdPartyProfiles_CreatesRBACProfileInTenantNamespace verifies that a
// component RBACProfile is created in seam-tenant-{clusterName}, not the component
// namespace. No PermissionSet or RBACPolicy is created. guardian-schema.md §19 Layer 3.
func TestThirdPartyProfiles_CreatesRBACProfileInTenantNamespace(t *testing.T) {
	const clusterName = "ccs-mgmt"
	const tenantNS = "seam-tenant-ccs-mgmt"
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(buildSA("cert-manager", "cert-manager")).
		Build()

	runnable := newThirdPartyRunnable(cl, clusterName)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// RBACProfile must be in seam-tenant-ccs-mgmt, not cert-manager.
	profile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: tenantNS, Name: "cert-manager"},
		profile,
	); err != nil {
		t.Fatalf("RBACProfile cert-manager not found in %s: %v", tenantNS, err)
	}
	if profile.Spec.RBACPolicyRef != "cluster-policy" {
		t.Errorf("RBACPolicyRef = %q, want cluster-policy", profile.Spec.RBACPolicyRef)
	}
	if len(profile.Spec.TargetClusters) != 1 || profile.Spec.TargetClusters[0] != clusterName {
		t.Errorf("TargetClusters = %v, want [%s]", profile.Spec.TargetClusters, clusterName)
	}
	if got := profile.GetLabels()["ontai.dev/policy-type"]; got != "component" {
		t.Errorf("policy-type label = %q, want component", got)
	}

	// Must NOT be in the component's own namespace.
	wrongProfile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: "cert-manager", Name: "cert-manager"},
		wrongProfile,
	); err == nil {
		t.Error("RBACProfile must NOT be in the component namespace cert-manager")
	}
}

// TestThirdPartyProfiles_NoPermissionSetOrRBACPolicyCreated verifies that bootstrap
// creates only RBACProfile -- no PermissionSet, no RBACPolicy. CS-INV-008.
func TestThirdPartyProfiles_NoPermissionSetOrRBACPolicyCreated(t *testing.T) {
	const clusterName = "ccs-mgmt"
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(buildSA("cert-manager", "cert-manager")).
		Build()

	runnable := newThirdPartyRunnable(cl, clusterName)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// No PermissionSet anywhere.
	psList := &securityv1alpha1.PermissionSetList{}
	if err := cl.List(context.Background(), psList); err != nil {
		t.Fatalf("list PermissionSets: %v", err)
	}
	if len(psList.Items) != 0 {
		t.Errorf("expected 0 PermissionSets (three-layer model: no per-component PermissionSet); got %d", len(psList.Items))
	}

	// No RBACPolicy anywhere.
	policyList := &securityv1alpha1.RBACPolicyList{}
	if err := cl.List(context.Background(), policyList); err != nil {
		t.Fatalf("list RBACPolicies: %v", err)
	}
	if len(policyList.Items) != 0 {
		t.Errorf("expected 0 RBACPolicies (three-layer model: no per-component RBACPolicy); got %d", len(policyList.Items))
	}
}

// TestThirdPartyProfiles_PrincipalRefUsesDiscoveredNamespace verifies that the
// RBACProfile.PrincipalRef uses the namespace where the SA was discovered, even
// though the profile itself lands in the tenant namespace.
func TestThirdPartyProfiles_PrincipalRefUsesDiscoveredNamespace(t *testing.T) {
	const clusterName = "ccs-mgmt"
	const tenantNS = "seam-tenant-ccs-mgmt"
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(buildSA("cert-manager", "custom-ns")).
		Build()

	runnable := newThirdPartyRunnable(cl, clusterName)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	profile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: tenantNS, Name: "cert-manager"},
		profile,
	); err != nil {
		t.Fatalf("RBACProfile not found: %v", err)
	}
	want := "system:serviceaccount:custom-ns:cert-manager"
	if profile.Spec.PrincipalRef != want {
		t.Errorf("PrincipalRef = %q, want %q", profile.Spec.PrincipalRef, want)
	}
}

// TestThirdPartyProfiles_SkipsComponentWhenSAAbsent verifies that no resources are
// created for a component whose SA cannot be found in any non-system namespace.
func TestThirdPartyProfiles_SkipsComponentWhenSAAbsent(t *testing.T) {
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	runnable := newThirdPartyRunnable(cl, "ccs-mgmt")

	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	profileList := &securityv1alpha1.RBACProfileList{}
	if err := cl.List(context.Background(), profileList); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	if len(profileList.Items) != 0 {
		t.Errorf("expected 0 RBACProfiles when no SAs present; got %d", len(profileList.Items))
	}
}

// TestThirdPartyProfiles_IsIdempotent verifies that running Start twice does not
// create duplicate resources and does not return an error.
func TestThirdPartyProfiles_IsIdempotent(t *testing.T) {
	const clusterName = "ccs-mgmt"
	const tenantNS = "seam-tenant-ccs-mgmt"
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(buildSA("cert-manager", "cert-manager")).
		Build()

	r1 := newThirdPartyRunnable(cl, clusterName)
	if err := r1.Start(context.Background()); err != nil {
		t.Fatalf("first Start: %v", err)
	}

	r2 := newThirdPartyRunnable(cl, clusterName)
	if err := r2.Start(context.Background()); err != nil {
		t.Fatalf("second Start: %v", err)
	}

	profileList := &securityv1alpha1.RBACProfileList{}
	if err := cl.List(context.Background(), profileList, client.InNamespace(tenantNS)); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	if len(profileList.Items) != 1 {
		t.Errorf("expected 1 RBACProfile after two runs; got %d", len(profileList.Items))
	}
}

// TestThirdPartyProfiles_DiscoversByServiceAccountName verifies that the principalRef
// uses whichever namespace the SA is actually installed in, not a hardcoded one.
// SA "kueue-controller-manager" in "tooling" -> principalRef uses "tooling".
func TestThirdPartyProfiles_DiscoversByServiceAccountName(t *testing.T) {
	const clusterName = "ccs-mgmt"
	const tenantNS = "seam-tenant-ccs-mgmt"
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(buildSA("kueue-controller-manager", "tooling")).
		Build()

	runnable := newThirdPartyRunnable(cl, clusterName)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	profile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: tenantNS, Name: "kueue"},
		profile,
	); err != nil {
		t.Errorf("RBACProfile kueue not found in %s: %v", tenantNS, err)
	}
	want := "system:serviceaccount:tooling:kueue-controller-manager"
	if profile.Spec.PrincipalRef != want {
		t.Errorf("PrincipalRef = %q, want %q", profile.Spec.PrincipalRef, want)
	}
}

// TestThirdPartyProfiles_NamespaceHintUsedOnCollision verifies that when the same
// SA name appears in multiple non-system namespaces, NamespaceHint is preferred.
func TestThirdPartyProfiles_NamespaceHintUsedOnCollision(t *testing.T) {
	const clusterName = "ccs-mgmt"
	const tenantNS = "seam-tenant-ccs-mgmt"
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			buildSA("cert-manager", "cert-manager"), // matches NamespaceHint
			buildSA("cert-manager", "other-ns"),
		).
		Build()

	runnable := newThirdPartyRunnable(cl, clusterName)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	profile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: tenantNS, Name: "cert-manager"},
		profile,
	); err != nil {
		t.Fatalf("RBACProfile cert-manager not found in %s: %v", tenantNS, err)
	}
	// PrincipalRef must use the hint namespace, not other-ns.
	want := "system:serviceaccount:cert-manager:cert-manager"
	if profile.Spec.PrincipalRef != want {
		t.Errorf("PrincipalRef = %q, want %q (hint namespace should win)", profile.Spec.PrincipalRef, want)
	}
}

// TestThirdPartyProfiles_SystemNamespaceSAsIgnored verifies that SAs found in system
// namespaces (kube-system, ont-system, seam-system) are not used for discovery.
func TestThirdPartyProfiles_SystemNamespaceSAsIgnored(t *testing.T) {
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			buildSA("cert-manager", "kube-system"),
			buildSA("cert-manager", "ont-system"),
			buildSA("cert-manager", "seam-system"),
		).
		Build()

	runnable := newThirdPartyRunnable(cl, "ccs-mgmt")
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	profileList := &securityv1alpha1.RBACProfileList{}
	if err := cl.List(context.Background(), profileList); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	if len(profileList.Items) != 0 {
		t.Errorf("expected 0 RBACProfiles when all matching SAs are in system namespaces; got %d",
			len(profileList.Items))
	}
}

// TestThirdPartyProfiles_SweepDoneSetAfterProfileCreation verifies SweepDone is true
// after Start completes and the profile is already present at that point.
func TestThirdPartyProfiles_SweepDoneSetAfterProfileCreation(t *testing.T) {
	const clusterName = "ccs-mgmt"
	const tenantNS = "seam-tenant-ccs-mgmt"
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(buildSA("metallb-controller", "metallb-system")).
		Build()

	sweepDone := &atomic.Bool{}
	runnable := &controller.BootstrapAnnotationRunnable{
		Client:                cl,
		SweepDone:             sweepDone,
		ManagementClusterName: clusterName,
	}

	if sweepDone.Load() {
		t.Fatal("SweepDone must be false before Start")
	}
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !sweepDone.Load() {
		t.Error("SweepDone must be true after Start")
	}

	profile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: tenantNS, Name: "metallb"},
		profile,
	); err != nil {
		t.Errorf("metallb RBACProfile not found in %s when SweepDone=true: %v", tenantNS, err)
	}
}

// Compile-time guard: BootstrapAnnotationRunnable must expose exported fields.
var _ = controller.BootstrapAnnotationRunnable{
	Client:                nil,
	SweepDone:             nil,
	ManagementClusterName: "",
}

// Compile-time guard: scheme must include rbacv1.
var _ = rbacv1.SchemeGroupVersion
