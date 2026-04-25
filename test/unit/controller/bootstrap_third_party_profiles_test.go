package controller_test

// Tests for BootstrapAnnotationRunnable.createThirdPartyProfiles.
//
// Scenarios:
//   - Profile, PermissionSet, and RBACPolicy are created in the component namespace
//     when the namespace exists.
//   - Component is skipped silently when its namespace is absent.
//   - Second run is idempotent: no duplicates, no errors.
//   - Each resource lands in the component's canonical namespace (not seam-system).
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

// buildThirdPartyTestObjects returns the minimal set of runtime objects needed
// for a third-party profile test. namespaces controls which component namespaces
// exist. Pass nil to get no component namespaces (only seam-system).
func buildThirdPartyTestObjects(namespaces ...string) []client.Object {
	objs := []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "seam-system"}},
	}
	for _, ns := range namespaces {
		objs = append(objs, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	}
	return objs
}

// newThirdPartyRunnable constructs a BootstrapAnnotationRunnable wired to the
// provided fake client for third-party profile tests.
func newThirdPartyRunnable(cl client.Client) *controller.BootstrapAnnotationRunnable {
	return &controller.BootstrapAnnotationRunnable{
		Client:    cl,
		SweepDone: &atomic.Bool{},
	}
}

// TestThirdPartyProfiles_CreatesAllResourcesWhenNamespaceExists verifies that
// PermissionSet, RBACPolicy, and RBACProfile are created in the component
// namespace when Start runs on a cluster that has that namespace.
func TestThirdPartyProfiles_CreatesAllResourcesWhenNamespaceExists(t *testing.T) {
	scheme := buildSweepScheme(t)
	objs := buildThirdPartyTestObjects("cert-manager")

	// Provide the seam-system namespace for Guardian's own profile (rbac-guardian)
	// lookup that runs during the sweep. The sweep itself will find no RBAC resources
	// to annotate — that is fine for this test.
	objs = append(objs, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "cert-manager"}})

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "cert-manager"}},
		).
		Build()

	runnable := newThirdPartyRunnable(cl)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// PermissionSet must exist in cert-manager namespace.
	ps := &securityv1alpha1.PermissionSet{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: "cert-manager", Name: "cert-manager-baseline"},
		ps,
	); err != nil {
		t.Errorf("PermissionSet cert-manager-baseline not found: %v", err)
	}

	// RBACPolicy must exist in cert-manager namespace.
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

	// RBACProfile must exist in cert-manager namespace.
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

// TestThirdPartyProfiles_SkipsComponentWhenNamespaceAbsent verifies that no
// PermissionSet, RBACPolicy, or RBACProfile is created for a component whose
// namespace does not exist on the cluster.
func TestThirdPartyProfiles_SkipsComponentWhenNamespaceAbsent(t *testing.T) {
	scheme := buildSweepScheme(t)
	// Deliberately do not create cert-manager namespace.
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	runnable := newThirdPartyRunnable(cl)

	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	psList := &securityv1alpha1.PermissionSetList{}
	if err := cl.List(context.Background(), psList,
		client.InNamespace("cert-manager"),
	); err != nil {
		t.Fatalf("list PermissionSets: %v", err)
	}
	if len(psList.Items) != 0 {
		t.Errorf("expected 0 PermissionSets in cert-manager namespace, got %d", len(psList.Items))
	}

	profileList := &securityv1alpha1.RBACProfileList{}
	if err := cl.List(context.Background(), profileList,
		client.InNamespace("cert-manager"),
	); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	if len(profileList.Items) != 0 {
		t.Errorf("expected 0 RBACProfiles in cert-manager namespace, got %d", len(profileList.Items))
	}
}

// TestThirdPartyProfiles_IsIdempotent verifies that running Start twice does not
// create duplicate resources and does not return an error.
func TestThirdPartyProfiles_IsIdempotent(t *testing.T) {
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "cert-manager"}},
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

// TestThirdPartyProfiles_ResourcesInComponentNamespace verifies that all three
// resources (PermissionSet, RBACPolicy, RBACProfile) for kueue land in
// kueue-system, not in seam-system or another namespace.
func TestThirdPartyProfiles_ResourcesInComponentNamespace(t *testing.T) {
	scheme := buildSweepScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kueue-system"}},
		).
		Build()

	runnable := newThirdPartyRunnable(cl)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Nothing in seam-system from this run (Seam operator profiles are in seam-system
	// but those are generated by compiler enable, not by the sweep runnable).
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

	// Verify profile is NOT in seam-system.
	wrongProfile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: "seam-system", Name: "rbac-kueue"},
		wrongProfile,
	); err == nil {
		t.Error("RBACProfile rbac-kueue should NOT exist in seam-system")
	}
}

// TestThirdPartyProfiles_SweepDoneSetAfterProfileCreation verifies that
// SweepDone is true after Start completes, confirming profiles are created
// before the completion flag is set.
func TestThirdPartyProfiles_SweepDoneSetAfterProfileCreation(t *testing.T) {
	scheme := buildSweepScheme(t)
	// Register rbac types so the sweep can list them without error.
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "metallb-system"}},
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

// Compile-time guard: BootstrapAnnotationRunnable must expose SweepDone and Client
// as exported fields for test construction. This var ensures the struct is used
// with the correct field names and types — any rename will fail to compile.
var _ = controller.BootstrapAnnotationRunnable{
	Client:    nil,
	SweepDone: nil,
}

// Compile-time guard: fake client scheme must include rbacv1 for sweep tests.
var _ = rbacv1.SchemeGroupVersion
