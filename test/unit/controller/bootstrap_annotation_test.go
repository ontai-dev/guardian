// Package controller_test contains unit tests for BootstrapAnnotationRunnable and
// BootstrapController sweep-complete gate.
//
// Tests cover:
//   - Sweep skips namespaces carrying seam.ontai.dev/webhook-mode=exempt.
//   - Sweep annotates unannotated RBAC resources in non-exempt namespaces.
//   - Sweep is idempotent: running twice produces the same result.
//   - BootstrapController blocks ObserveOnly advance when SweepDone=false.
//   - BootstrapController advances to ObserveOnly when SweepDone=true and all
//     profiles are provisioned.
//
// guardian-schema.md §4. INV-020, CS-INV-004.
package controller_test

import (
	"context"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	clientevents "k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
	"github.com/ontai-dev/guardian/internal/webhook"
	ctrl "sigs.k8s.io/controller-runtime"
)

// buildSweepScheme returns a Scheme with core + rbac + security API groups registered.
func buildSweepScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(securityv1alpha1.AddToScheme(s))
	return s
}

// makeNamespace builds a Namespace object with optional labels.
func makeNamespace(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
	}
}

// makeRole builds an unannotated Role in the given namespace.
func makeRole(name, ns string) *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
	}
}

// makeClusterRole builds an unannotated ClusterRole.
func makeClusterRole(name string) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
}

// makeServiceAccount builds an unannotated ServiceAccount.
func makeServiceAccount(name, ns string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
	}
}

// makeAnnotatedRole builds a Role already carrying ontai.dev/rbac-owner=guardian.
func makeAnnotatedRole(name, ns string) *rbacv1.Role {
	r := makeRole(name, ns)
	r.Annotations = map[string]string{
		webhook.AnnotationRBACOwner: webhook.AnnotationRBACOwnerValue,
	}
	return r
}

// buildSweepRunnable constructs a BootstrapAnnotationRunnable with a fake client
// pre-populated with the given objects, and returns the runnable and its sweepDone bool.
func buildSweepRunnable(t *testing.T, objs ...runtime.Object) (*controller.BootstrapAnnotationRunnable, *atomic.Bool) {
	t.Helper()
	s := buildSweepScheme(t)
	builder := fake.NewClientBuilder().WithScheme(s)
	for _, o := range objs {
		builder = builder.WithRuntimeObjects(o)
	}
	c := builder.Build()
	done := &atomic.Bool{}
	return &controller.BootstrapAnnotationRunnable{
		Client:    c,
		SweepDone: done,
	}, done
}

// Test 1 — Sweep skips exempt namespaces.
// Namespaces with seam.ontai.dev/webhook-mode=exempt must be skipped entirely.
// Resources inside them must NOT be annotated by the sweep. CS-INV-004.
func TestBootstrapAnnotationSweep_SkipsExemptNamespaces(t *testing.T) {
	exemptNS := makeNamespace("seam-system", map[string]string{
		webhook.WebhookModeLabelKey: string(webhook.NamespaceModeExempt),
	})
	role := makeRole("guardian-manager", "seam-system")

	runnable, done := buildSweepRunnable(t, exemptNS, role)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	if !done.Load() {
		t.Fatal("SweepDone must be true after Start completes")
	}

	// The role in the exempt namespace must NOT have been annotated.
	result := &rbacv1.Role{}
	if err := runnable.Client.Get(context.Background(), types.NamespacedName{
		Name: "guardian-manager", Namespace: "seam-system",
	}, result); err != nil {
		t.Fatalf("get role: %v", err)
	}
	if result.Annotations[webhook.AnnotationRBACOwner] == webhook.AnnotationRBACOwnerValue {
		t.Error("exempt namespace role must not be annotated by sweep")
	}
}

// Test 2 — Sweep annotates unannotated resources in non-exempt namespaces.
// Roles, ClusterRoles, and ServiceAccounts missing the ownership annotation
// must receive ontai.dev/rbac-owner=guardian and ontai.dev/rbac-enforcement-mode=audit.
func TestBootstrapAnnotationSweep_AnnotatesUnannotatedResources(t *testing.T) {
	ns := makeNamespace("ont-system", nil)
	role := makeRole("platform-manager", "ont-system")
	cr := makeClusterRole("platform-cluster-role")
	sa := makeServiceAccount("platform-sa", "ont-system")

	runnable, done := buildSweepRunnable(t, ns, role, cr, sa)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	if !done.Load() {
		t.Fatal("SweepDone must be true after Start completes")
	}

	// Role must be annotated.
	gotRole := &rbacv1.Role{}
	if err := runnable.Client.Get(context.Background(), types.NamespacedName{
		Name: "platform-manager", Namespace: "ont-system",
	}, gotRole); err != nil {
		t.Fatalf("get role: %v", err)
	}
	if gotRole.Annotations[webhook.AnnotationRBACOwner] != webhook.AnnotationRBACOwnerValue {
		t.Errorf("role: want ontai.dev/rbac-owner=guardian, got %q", gotRole.Annotations[webhook.AnnotationRBACOwner])
	}
	if gotRole.Annotations[controller.AnnotationRBACEnforcementMode] != controller.AnnotationRBACEnforcementModeAudit {
		t.Errorf("role: want ontai.dev/rbac-enforcement-mode=audit, got %q", gotRole.Annotations[controller.AnnotationRBACEnforcementMode])
	}

	// ClusterRole must be annotated.
	gotCR := &rbacv1.ClusterRole{}
	if err := runnable.Client.Get(context.Background(), types.NamespacedName{
		Name: "platform-cluster-role",
	}, gotCR); err != nil {
		t.Fatalf("get clusterrole: %v", err)
	}
	if gotCR.Annotations[webhook.AnnotationRBACOwner] != webhook.AnnotationRBACOwnerValue {
		t.Errorf("clusterrole: want ontai.dev/rbac-owner=guardian, got %q", gotCR.Annotations[webhook.AnnotationRBACOwner])
	}

	// ServiceAccount must be annotated.
	gotSA := &corev1.ServiceAccount{}
	if err := runnable.Client.Get(context.Background(), types.NamespacedName{
		Name: "platform-sa", Namespace: "ont-system",
	}, gotSA); err != nil {
		t.Fatalf("get serviceaccount: %v", err)
	}
	if gotSA.Annotations[webhook.AnnotationRBACOwner] != webhook.AnnotationRBACOwnerValue {
		t.Errorf("serviceaccount: want ontai.dev/rbac-owner=guardian, got %q", gotSA.Annotations[webhook.AnnotationRBACOwner])
	}
}

// Test 3 — Sweep is idempotent.
// Running Start twice on the same resources produces the same annotations.
// The second run must not change or remove annotations set by the first.
func TestBootstrapAnnotationSweep_Idempotent(t *testing.T) {
	ns := makeNamespace("ont-system", nil)
	role := makeRole("platform-manager", "ont-system")

	runnable, _ := buildSweepRunnable(t, ns, role)

	// First run.
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("first Start error: %v", err)
	}

	// Reset SweepDone so Start may be called again.
	runnable.SweepDone.Store(false)

	// Second run.
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("second Start error: %v", err)
	}

	gotRole := &rbacv1.Role{}
	if err := runnable.Client.Get(context.Background(), types.NamespacedName{
		Name: "platform-manager", Namespace: "ont-system",
	}, gotRole); err != nil {
		t.Fatalf("get role: %v", err)
	}
	if gotRole.Annotations[webhook.AnnotationRBACOwner] != webhook.AnnotationRBACOwnerValue {
		t.Errorf("idempotent: want ontai.dev/rbac-owner=guardian after second run, got %q",
			gotRole.Annotations[webhook.AnnotationRBACOwner])
	}
}

// Test: system: prefixed ClusterRoles are skipped by the sweep.
// Kubernetes built-in ClusterRoles (e.g. system:kube-controller-manager) must never
// be annotated — patching them risks corrupting system RBAC. CS-INV-007.
func TestBootstrapAnnotationSweep_SkipsSystemPrefixedClusterRoles(t *testing.T) {
	ns := makeNamespace("ont-system", nil)
	systemCR := makeClusterRole("system:kube-controller-manager")
	regularCR := makeClusterRole("platform-cluster-role")

	runnable, done := buildSweepRunnable(t, ns, systemCR, regularCR)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	if !done.Load() {
		t.Fatal("SweepDone must be true after Start completes")
	}

	// system: ClusterRole must NOT be annotated.
	gotSystem := &rbacv1.ClusterRole{}
	if err := runnable.Client.Get(context.Background(), types.NamespacedName{
		Name: "system:kube-controller-manager",
	}, gotSystem); err != nil {
		t.Fatalf("get system ClusterRole: %v", err)
	}
	if gotSystem.Annotations[webhook.AnnotationRBACOwner] == webhook.AnnotationRBACOwnerValue {
		t.Error("system: ClusterRole must not be annotated by sweep")
	}

	// Regular ClusterRole must still be annotated.
	gotRegular := &rbacv1.ClusterRole{}
	if err := runnable.Client.Get(context.Background(), types.NamespacedName{
		Name: "platform-cluster-role",
	}, gotRegular); err != nil {
		t.Fatalf("get regular ClusterRole: %v", err)
	}
	if gotRegular.Annotations[webhook.AnnotationRBACOwner] != webhook.AnnotationRBACOwnerValue {
		t.Errorf("regular ClusterRole: want ontai.dev/rbac-owner=guardian, got %q",
			gotRegular.Annotations[webhook.AnnotationRBACOwner])
	}
}

// Test 4 — Sweep does not annotate already-owned resources.
// Resources that already carry ontai.dev/rbac-owner=guardian must be counted as
// already-owned and left untouched (no enforcement-mode stamp added by sweep).
func TestBootstrapAnnotationSweep_SkipsAlreadyOwnedResources(t *testing.T) {
	ns := makeNamespace("ont-system", nil)
	owned := makeAnnotatedRole("already-owned", "ont-system")
	// The role already has ontai.dev/rbac-owner=guardian but no enforcement-mode.
	// After sweep, enforcement-mode should still be absent (sweep skips it).

	runnable, done := buildSweepRunnable(t, ns, owned)
	if err := runnable.Start(context.Background()); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	if !done.Load() {
		t.Fatal("SweepDone must be true after Start")
	}

	got := &rbacv1.Role{}
	if err := runnable.Client.Get(context.Background(), types.NamespacedName{
		Name: "already-owned", Namespace: "ont-system",
	}, got); err != nil {
		t.Fatalf("get role: %v", err)
	}
	// The sweep does not patch already-owned resources, so enforcement-mode is absent.
	if got.Annotations[controller.AnnotationRBACEnforcementMode] != "" {
		t.Errorf("already-owned role: enforcement-mode annotation should be absent, got %q",
			got.Annotations[controller.AnnotationRBACEnforcementMode])
	}
}

// buildBootstrapReconcilerWithSweep is identical to buildBootstrapReconciler but
// passes a pre-configured SweepDone atomic bool to the controller.
func buildBootstrapReconcilerWithSweep(
	t *testing.T,
	sweepDone *atomic.Bool,
	objs ...runtime.Object,
) *controller.BootstrapController {
	t.Helper()
	s := buildBootstrapScheme(t)
	builder := fake.NewClientBuilder().WithScheme(s)
	for _, o := range objs {
		builder = builder.WithRuntimeObjects(o)
	}
	c := builder.WithStatusSubresource(&securityv1alpha1.Guardian{}, &securityv1alpha1.RBACProfile{}).Build()
	gate := webhook.NewWebhookModeGate()
	registry := webhook.NewNamespaceEnforcementRegistry()
	return &controller.BootstrapController{
		Client:            c,
		Scheme:            s,
		Recorder:          clientevents.NewFakeRecorder(32),
		Gate:              gate,
		Registry:          registry,
		OperatorNamespace: "seam-system",
		SweepDone:         sweepDone,
	}
}

// Test 5 — BootstrapController blocks ObserveOnly advance when SweepDone=false.
// Even when all RBACProfiles are provisioned, the controller must requeue with a
// 5s backoff rather than advancing to ObserveOnly when the sweep is incomplete.
func TestBootstrapController_BlocksObserveOnlyWhenSweepNotComplete(t *testing.T) {
	p := buildProvisionedProfile("guardian-profile", "seam-system")
	done := &atomic.Bool{} // starts false
	r := buildBootstrapReconcilerWithSweep(t, done, p)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      controller.GuardianSingletonName,
			Namespace: "seam-system",
		},
	})
	if err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("expected RequeueAfter > 0 when sweep not complete")
	}

	// Mode must still be Initialising — advance must not have happened.
	gdn := &securityv1alpha1.Guardian{}
	if err := r.Client.Get(context.Background(), types.NamespacedName{
		Name:      controller.GuardianSingletonName,
		Namespace: "seam-system",
	}, gdn); err != nil {
		t.Fatalf("get Guardian: %v", err)
	}
	if gdn.Status.WebhookMode != securityv1alpha1.WebhookModeInitialising {
		t.Errorf("WebhookMode = %q, want Initialising while sweep incomplete", gdn.Status.WebhookMode)
	}
}

// Test 6 — BootstrapController advances to ObserveOnly when SweepDone=true and all
// profiles are provisioned. The gate transitions normally once the sweep is complete.
func TestBootstrapController_AdvancesObserveOnlyWhenSweepComplete(t *testing.T) {
	p := buildProvisionedProfile("guardian-profile", "seam-system")
	done := &atomic.Bool{}
	done.Store(true) // sweep complete
	r := buildBootstrapReconcilerWithSweep(t, done, p)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      controller.GuardianSingletonName,
			Namespace: "seam-system",
		},
	})
	if err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}

	gdn := &securityv1alpha1.Guardian{}
	if err := r.Client.Get(context.Background(), types.NamespacedName{
		Name:      controller.GuardianSingletonName,
		Namespace: "seam-system",
	}, gdn); err != nil {
		t.Fatalf("get Guardian: %v", err)
	}
	if gdn.Status.WebhookMode != securityv1alpha1.WebhookModeObserveOnly {
		t.Errorf("WebhookMode = %q, want ObserveOnly when sweep complete and profiles ready", gdn.Status.WebhookMode)
	}
}
