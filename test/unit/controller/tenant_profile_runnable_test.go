// Package controller_test contains unit tests for TenantProfileRunnable.
//
// TenantProfileRunnable creates RBACProfiles in Namespace (ont-system) on the
// tenant cluster for each discovered third-party component. Under the three-layer
// RBAC hierarchy (guardian-schema.md §19, CS-INV-008):
//   - No per-component PermissionSet is created.
//   - No per-component RBACPolicy is created.
//   - Each RBACProfile references ClusterPolicyName ("cluster-policy").
//   - ClusterMaximumPermSetName ("cluster-maximum") is the sole permission ceiling.
//   - SA discovery across non-system namespaces; NamespaceHint breaks ties.
//
// guardian-schema.md §15, §19. CS-INV-008.
package controller_test

import (
	"context"
	"testing"
	"time"

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

func buildTenantProfileScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(securityv1alpha1.AddToScheme(s))
	return s
}

// newTenantProfileRunnable constructs a TenantProfileRunnable with the given
// client, namespace, and clusterID. Interval is set to 1 hour to ensure only
// the initial runOnce call fires in tests driven by Start with a cancelled ctx.
func newTenantProfileRunnable(cl client.Client, namespace, clusterID string) *controller.TenantProfileRunnable {
	return &controller.TenantProfileRunnable{
		Client:    cl,
		Namespace: namespace,
		ClusterID: clusterID,
		Interval:  time.Hour,
	}
}

// runProfileOnce calls Start with an already-cancelled context so that only the
// initial runOnce executes before the loop exits.
func runProfileOnce(t *testing.T, r *controller.TenantProfileRunnable) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("TenantProfileRunnable.Start: %v", err)
	}
}

// TestTenantProfileRunnable_CreatesRBACProfileInNamespace verifies that a component
// RBACProfile is created in Namespace (ont-system), not in the component namespace.
// PrincipalRef reflects the discovered namespace. guardian-schema.md §15, §19 Layer 3.
func TestTenantProfileRunnable_CreatesRBACProfileInNamespace(t *testing.T) {
	const namespace = "ont-system"
	const clusterID = "ccs-dev"
	scheme := buildTenantProfileScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(buildSA("cert-manager", "cert-manager")).
		Build()

	r := newTenantProfileRunnable(cl, namespace, clusterID)
	runProfileOnce(t, r)

	profile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: namespace, Name: "cert-manager"},
		profile,
	); err != nil {
		t.Fatalf("RBACProfile cert-manager not found in %s: %v", namespace, err)
	}
	// RBACPolicyRef must be empty on tenant clusters. The governance ceiling lives
	// on the management cluster; the PermissionSnapshot is the computed oracle.
	// GUARDIAN-BL-RBACPROFILE-TENANT-PROVISIONING.
	if profile.Spec.RBACPolicyRef != "" {
		t.Errorf("RBACPolicyRef = %q, want empty (tenant clusters carry no local cluster-policy)", profile.Spec.RBACPolicyRef)
	}
	wantPrincipal := "system:serviceaccount:cert-manager:cert-manager"
	if profile.Spec.PrincipalRef != wantPrincipal {
		t.Errorf("PrincipalRef = %q, want %q", profile.Spec.PrincipalRef, wantPrincipal)
	}
	if got := profile.GetLabels()["ontai.dev/policy-type"]; got != "component" {
		t.Errorf("policy-type label = %q, want component", got)
	}
	if len(profile.Spec.PermissionDeclarations) != 1 ||
		profile.Spec.PermissionDeclarations[0].PermissionSetRef != "cluster-maximum" {
		t.Errorf("PermissionDeclarations = %v, want [{cluster-maximum cluster}]",
			profile.Spec.PermissionDeclarations)
	}
	// Profile must NOT land in the component namespace.
	wrongProfile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: "cert-manager", Name: "cert-manager"},
		wrongProfile,
	); err == nil {
		t.Error("RBACProfile must NOT be in the component namespace cert-manager")
	}
}

// TestTenantProfileRunnable_NoPermissionSetOrRBACPolicyCreated verifies that
// TenantProfileRunnable creates only RBACProfiles. No PermissionSet, no RBACPolicy.
// CS-INV-008: three-layer hierarchy permits only Layer 3 (component RBACProfile).
func TestTenantProfileRunnable_NoPermissionSetOrRBACPolicyCreated(t *testing.T) {
	scheme := buildTenantProfileScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(buildSA("cert-manager", "cert-manager")).
		Build()

	r := newTenantProfileRunnable(cl, "ont-system", "ccs-dev")
	runProfileOnce(t, r)

	psList := &securityv1alpha1.PermissionSetList{}
	if err := cl.List(context.Background(), psList); err != nil {
		t.Fatalf("list PermissionSets: %v", err)
	}
	if len(psList.Items) != 0 {
		t.Errorf("CS-INV-008: expected 0 PermissionSets; got %d", len(psList.Items))
	}

	policyList := &securityv1alpha1.RBACPolicyList{}
	if err := cl.List(context.Background(), policyList); err != nil {
		t.Fatalf("list RBACPolicies: %v", err)
	}
	if len(policyList.Items) != 0 {
		t.Errorf("CS-INV-008: expected 0 RBACPolicies; got %d", len(policyList.Items))
	}
}

// TestTenantProfileRunnable_SkipsComponentWhenSAAbsent verifies that no RBACProfile
// is created for a component whose ServiceAccount cannot be found.
func TestTenantProfileRunnable_SkipsComponentWhenSAAbsent(t *testing.T) {
	scheme := buildTenantProfileScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := newTenantProfileRunnable(cl, "ont-system", "ccs-dev")
	runProfileOnce(t, r)

	profileList := &securityv1alpha1.RBACProfileList{}
	if err := cl.List(context.Background(), profileList); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	if len(profileList.Items) != 0 {
		t.Errorf("expected 0 RBACProfiles when no SAs present; got %d", len(profileList.Items))
	}
}

// TestTenantProfileRunnable_IsIdempotent verifies that running twice does not create
// duplicate RBACProfiles and does not return an error.
func TestTenantProfileRunnable_IsIdempotent(t *testing.T) {
	const namespace = "ont-system"
	scheme := buildTenantProfileScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(buildSA("cert-manager", "cert-manager")).
		Build()

	r := newTenantProfileRunnable(cl, namespace, "ccs-dev")
	runProfileOnce(t, r)
	runProfileOnce(t, r)

	profileList := &securityv1alpha1.RBACProfileList{}
	if err := cl.List(context.Background(), profileList, client.InNamespace(namespace)); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	var certMgrCount int
	for _, p := range profileList.Items {
		if p.Name == "cert-manager" {
			certMgrCount++
		}
	}
	if certMgrCount != 1 {
		t.Errorf("expected exactly 1 cert-manager RBACProfile after two runs; got %d", certMgrCount)
	}
}

// TestTenantProfileRunnable_NamespaceHintWinsOnCollision verifies that when the same
// SA name appears in multiple non-system namespaces, NamespaceHint is preferred.
func TestTenantProfileRunnable_NamespaceHintWinsOnCollision(t *testing.T) {
	const namespace = "ont-system"
	scheme := buildTenantProfileScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			buildSA("cert-manager", "cert-manager"), // matches NamespaceHint
			buildSA("cert-manager", "other-ns"),
		).
		Build()

	r := newTenantProfileRunnable(cl, namespace, "ccs-dev")
	runProfileOnce(t, r)

	profile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: namespace, Name: "cert-manager"},
		profile,
	); err != nil {
		t.Fatalf("RBACProfile not found: %v", err)
	}
	want := "system:serviceaccount:cert-manager:cert-manager"
	if profile.Spec.PrincipalRef != want {
		t.Errorf("PrincipalRef = %q, want %q (NamespaceHint must win on collision)", profile.Spec.PrincipalRef, want)
	}
}

// TestTenantProfileRunnable_SystemNamespaceSAsIgnored verifies that SAs found in
// system namespaces are excluded from discovery. guardian-schema.md §15.
func TestTenantProfileRunnable_SystemNamespaceSAsIgnored(t *testing.T) {
	scheme := buildTenantProfileScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "cert-manager", Namespace: "kube-system"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "cert-manager", Namespace: "ont-system"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "cert-manager", Namespace: "seam-system"}},
		).
		Build()

	r := newTenantProfileRunnable(cl, "ont-system", "ccs-dev")
	runProfileOnce(t, r)

	profileList := &securityv1alpha1.RBACProfileList{}
	if err := cl.List(context.Background(), profileList); err != nil {
		t.Fatalf("list RBACProfiles: %v", err)
	}
	if len(profileList.Items) != 0 {
		t.Errorf("expected 0 RBACProfiles when all SAs are in system namespaces; got %d",
			len(profileList.Items))
	}
}

// TestTenantProfileRunnable_TargetClustersSetToClusterID verifies that the RBACProfile
// TargetClusters field is set to the TenantProfileRunnable.ClusterID.
func TestTenantProfileRunnable_TargetClustersSetToClusterID(t *testing.T) {
	const namespace = "ont-system"
	const clusterID = "ccs-dev"
	scheme := buildTenantProfileScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(buildSA("kueue-controller-manager", "kueue")).
		Build()

	r := newTenantProfileRunnable(cl, namespace, clusterID)
	runProfileOnce(t, r)

	profile := &securityv1alpha1.RBACProfile{}
	if err := cl.Get(context.Background(),
		client.ObjectKey{Namespace: namespace, Name: "kueue"},
		profile,
	); err != nil {
		t.Fatalf("RBACProfile kueue not found: %v", err)
	}
	if len(profile.Spec.TargetClusters) != 1 || profile.Spec.TargetClusters[0] != clusterID {
		t.Errorf("TargetClusters = %v, want [%s]", profile.Spec.TargetClusters, clusterID)
	}
}

// Compile-time guard: TenantProfileRunnable must expose exported fields.
var _ = controller.TenantProfileRunnable{
	Client:    nil,
	Namespace: "",
	ClusterID: "",
	Interval:  0,
}
