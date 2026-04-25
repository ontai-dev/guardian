package controller_test

// Tests for BootstrapAnnotationRunnable.createThirdPartyProfiles.
//
// The SA-discovery redesign (CS-INV-007) means component namespace is determined
// at runtime by listing ServiceAccounts across all non-system namespaces and
// matching by ServiceAccountName, not by a hardcoded namespace catalog.
//
// Scenarios:
//   - Profile, PermissionSet, and RBACPolicy are created in the namespace where
//     the component's ServiceAccount is discovered.
//   - Component is skipped when its SA cannot be found in any non-system namespace.
//   - Second run is idempotent: no duplicates, no errors.
//   - Discovery uses the discovered namespace (not a hardcoded value).
//   - NamespaceHint is used as a tiebreaker when the SA name matches in multiple namespaces.
//   - PrincipalRef reflects the discovered namespace.
//
// guardian-schema.md §3 Step 2, §6.

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

// buildSA constructs a ServiceAccount with the given name and namespace for use
// in fake client setups. The SA is what discovery uses to locate component namespaces.
func buildSA(name, ns string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
	}
}

// newThirdPartyRunnable constructs a BootstrapAnnotationRunnable wired to the
// provided fake client for third-party profile tests.
func newThirdPartyRunnable(cl client.Client) *controller.BootstrapAnnotationRunnable {
	return &controller.BootstrapAnnotationRunnable{
		Client:    cl,
		SweepDone: &atomic.Bool{},
	}
}

// TestThirdPartyProfiles_CreatesAllResourcesWhenSADiscovered verifies that
// PermissionSet, RBACPolicy, and RBACProfile are created in the namespace where
// the component's ServiceAccount is discovered.
func TestThirdPartyProfiles_CreatesAllResourcesWhenSADiscovered(t *testing.T) {
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			buildSA("cert-manager", "cert-manager"),
		).
		Build()

	runnable := newThirdPartyRunnable(cl)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// PermissionSet must exist in the discovered namespace (cert-manager).
	ps := &securityv1alpha1.PermissionSet{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: "cert-manager", Name: "cert-manager-baseline"},
		ps,
	); err != nil {
		t.Errorf("PermissionSet cert-manager-baseline not found: %v", err)
	}

	// RBACPolicy must exist in the discovered namespace.
	policy := &securityv1alpha1.RBACPolicy{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: "cert-manager", Name: "cert-manager-rbac-policy"},
		policy,
	); err != nil {
		t.Errorf("RBACPolicy cert-manager-rbac-policy not found: %v", err)
	}
	if policy.Spec.SubjectScope != securityv1alpha1.SubjectScopePlatform {
		t.Errorf("RBACPolicy.SubjectScope = %q, want platform", policy.Spec.SubjectScope)
	}
	if policy.Spec.EnforcementMode != securityv1alpha1.EnforcementModeStrict {
		t.Errorf("RBACPolicy.EnforcementMode = %q, want strict", policy.Spec.EnforcementMode)
	}

	// RBACProfile must exist in the discovered namespace.
	profile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: "cert-manager", Name: "rbac-cert-manager"},
		profile,
	); err != nil {
		t.Errorf("RBACProfile rbac-cert-manager not found: %v", err)
	}
	if profile.Spec.PrincipalRef != "system:serviceaccount:cert-manager:cert-manager" {
		t.Errorf("RBACProfile.PrincipalRef = %q, want system:serviceaccount:cert-manager:cert-manager",
			profile.Spec.PrincipalRef)
	}
	if len(profile.Spec.PermissionDeclarations) != 1 {
		t.Errorf("RBACProfile.PermissionDeclarations length = %d, want 1",
			len(profile.Spec.PermissionDeclarations))
	}
	if profile.Spec.RBACPolicyRef != "cert-manager-rbac-policy" {
		t.Errorf("RBACProfile.RBACPolicyRef = %q, want cert-manager-rbac-policy",
			profile.Spec.RBACPolicyRef)
	}
}

// TestThirdPartyProfiles_SkipsComponentWhenSAAbsent verifies that no resources are
// created for a component whose ServiceAccount cannot be found in any non-system namespace.
func TestThirdPartyProfiles_SkipsComponentWhenSAAbsent(t *testing.T) {
	scheme := buildSweepScheme(t)
	// No cert-manager SA anywhere.
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	runnable := newThirdPartyRunnable(cl)

	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	psList := &securityv1alpha1.PermissionSetList{}
	if err := cl.List(context.Background(), psList); err != nil {
		t.Fatalf("list PermissionSets: %v", err)
	}
	if len(psList.Items) != 0 {
		t.Errorf("expected 0 PermissionSets when no SAs present, got %d", len(psList.Items))
	}

	profileList := &securityv1alpha1.RBACProfileList{}
	if err := cl.List(context.Background(), profileList); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	if len(profileList.Items) != 0 {
		t.Errorf("expected 0 RBACProfiles when no SAs present, got %d", len(profileList.Items))
	}
}

// TestThirdPartyProfiles_IsIdempotent verifies that running Start twice does not
// create duplicate resources and does not return an error.
func TestThirdPartyProfiles_IsIdempotent(t *testing.T) {
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			buildSA("cert-manager", "cert-manager"),
		).
		Build()

	r1 := newThirdPartyRunnable(cl)
	if err := r1.Start(context.Background()); err != nil {
		t.Fatalf("first Start: %v", err)
	}

	r2 := newThirdPartyRunnable(cl)
	if err := r2.Start(context.Background()); err != nil {
		t.Fatalf("second Start: %v", err)
	}

	// Exactly one RBACProfile for cert-manager.
	profileList := &securityv1alpha1.RBACProfileList{}
	if err := cl.List(context.Background(), profileList,
		client.InNamespace("cert-manager"),
	); err != nil {
		t.Fatalf("list profiles: %v", err)
	}
	if len(profileList.Items) != 1 {
		t.Errorf("expected 1 RBACProfile after two runs, got %d", len(profileList.Items))
	}

	// Exactly one PermissionSet for cert-manager.
	psList := &securityv1alpha1.PermissionSetList{}
	if err := cl.List(context.Background(), psList,
		client.InNamespace("cert-manager"),
	); err != nil {
		t.Fatalf("list PermissionSets: %v", err)
	}
	if len(psList.Items) != 1 {
		t.Errorf("expected 1 PermissionSet after two runs, got %d", len(psList.Items))
	}
}

// TestThirdPartyProfiles_DiscoversByServiceAccountName verifies that profiles land
// in whichever namespace the SA is actually installed, not a hardcoded one.
// SA "kueue-controller-manager" in "tooling" -> profiles created in "tooling".
func TestThirdPartyProfiles_DiscoversByServiceAccountName(t *testing.T) {
	scheme := buildSweepScheme(t)
	// Kueue installed in "tooling" instead of the conventional "kueue-system".
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			buildSA("kueue-controller-manager", "tooling"),
		).
		Build()

	runnable := newThirdPartyRunnable(cl)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Profile must be in "tooling", not "kueue-system".
	profile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: "tooling", Name: "rbac-kueue"},
		profile,
	); err != nil {
		t.Errorf("RBACProfile rbac-kueue not found in discovered namespace 'tooling': %v", err)
	}

	// Must NOT exist in any other namespace.
	wrongProfile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: "kueue-system", Name: "rbac-kueue"},
		wrongProfile,
	); err == nil {
		t.Error("RBACProfile rbac-kueue should NOT exist in kueue-system when SA is in 'tooling'")
	}
}

// TestThirdPartyProfiles_NamespaceHintUsedOnCollision verifies that when the same
// SA name appears in multiple non-system namespaces, NamespaceHint is preferred.
// cert-manager SA is in both "cert-manager" (hint) and "other-ns".
func TestThirdPartyProfiles_NamespaceHintUsedOnCollision(t *testing.T) {
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			buildSA("cert-manager", "cert-manager"), // matches NamespaceHint
			buildSA("cert-manager", "other-ns"),
		).
		Build()

	runnable := newThirdPartyRunnable(cl)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Profile must be in the hint namespace.
	profile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: "cert-manager", Name: "rbac-cert-manager"},
		profile,
	); err != nil {
		t.Errorf("RBACProfile rbac-cert-manager not found in hint namespace 'cert-manager': %v", err)
	}

	// Must NOT be in the other namespace.
	wrongProfile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: "other-ns", Name: "rbac-cert-manager"},
		wrongProfile,
	); err == nil {
		t.Error("RBACProfile rbac-cert-manager should NOT exist in 'other-ns' when hint is 'cert-manager'")
	}
}

// TestThirdPartyProfiles_PrincipalRefUsesDiscoveredNamespace verifies that the
// RBACProfile.PrincipalRef is built using the discovered namespace, not any
// hardcoded value. SA "cert-manager" in "custom-ns" -> principalRef uses "custom-ns".
func TestThirdPartyProfiles_PrincipalRefUsesDiscoveredNamespace(t *testing.T) {
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			buildSA("cert-manager", "custom-ns"),
		).
		Build()

	runnable := newThirdPartyRunnable(cl)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	profile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: "custom-ns", Name: "rbac-cert-manager"},
		profile,
	); err != nil {
		t.Fatalf("RBACProfile not found: %v", err)
	}
	want := "system:serviceaccount:custom-ns:cert-manager"
	if profile.Spec.PrincipalRef != want {
		t.Errorf("PrincipalRef = %q, want %q", profile.Spec.PrincipalRef, want)
	}
}

// TestThirdPartyProfiles_SystemNamespaceSAsIgnored verifies that SAs found in
// system namespaces (kube-system, ont-system, seam-system) are not used for
// discovery — only non-system namespaces are eligible.
func TestThirdPartyProfiles_SystemNamespaceSAsIgnored(t *testing.T) {
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			// SAs in system namespaces must be ignored.
			buildSA("cert-manager", "kube-system"),
			buildSA("cert-manager", "ont-system"),
			buildSA("cert-manager", "seam-system"),
		).
		Build()

	runnable := newThirdPartyRunnable(cl)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// No profile should be created — all matching SAs are in system namespaces.
	profileList := &securityv1alpha1.RBACProfileList{}
	if err := cl.List(context.Background(), profileList); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	if len(profileList.Items) != 0 {
		t.Errorf("expected 0 RBACProfiles when all matching SAs are in system namespaces, got %d",
			len(profileList.Items))
	}
}

// TestThirdPartyProfiles_SweepDoneSetAfterProfileCreation verifies that
// SweepDone is true after Start completes, confirming profiles are created
// before the completion flag is set.
func TestThirdPartyProfiles_SweepDoneSetAfterProfileCreation(t *testing.T) {
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			buildSA("metallb-controller", "metallb-system"),
		).
		Build()

	sweepDone := &atomic.Bool{}
	runnable := &controller.BootstrapAnnotationRunnable{
		Client:    cl,
		SweepDone: sweepDone,
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

	// metallb profile must already be present when SweepDone becomes true.
	profile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: "metallb-system", Name: "rbac-metallb"},
		profile,
	); err != nil {
		t.Errorf("rbac-metallb not found when SweepDone=true: %v", err)
	}
}

// TestThirdPartyProfiles_ResourcesNotInSeamSystem verifies that third-party profile
// resources created for kueue land in its discovered namespace, not in seam-system.
func TestThirdPartyProfiles_ResourcesNotInSeamSystem(t *testing.T) {
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			buildSA("kueue-controller-manager", "kueue-system"),
		).
		Build()

	runnable := newThirdPartyRunnable(cl)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Nothing in seam-system from this run.
	psList := &securityv1alpha1.PermissionSetList{}
	if err := cl.List(context.Background(), psList, client.InNamespace("seam-system")); err != nil {
		t.Fatalf("list seam-system PermissionSets: %v", err)
	}
	if len(psList.Items) != 0 {
		t.Errorf("expected 0 PermissionSets in seam-system from sweep, got %d", len(psList.Items))
	}

	// kueue-system must have the profile.
	profile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: "kueue-system", Name: "rbac-kueue"},
		profile,
	); err != nil {
		t.Errorf("RBACProfile rbac-kueue not in kueue-system: %v", err)
	}
}

// Compile-time guard: BootstrapAnnotationRunnable must expose SweepDone and Client
// as exported fields for test construction.
var _ = controller.BootstrapAnnotationRunnable{
	Client:    nil,
	SweepDone: nil,
}

// Compile-time guard: fake client scheme must include rbacv1 for sweep tests.
var _ = rbacv1.SchemeGroupVersion
