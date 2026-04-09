// Package controller_test contains unit tests for the BootstrapController.
//
// Tests cover:
//   - Singleton Guardian CR creation on first reconcile.
//   - Startup sequence: WebhookMode=Initialising on creation.
//   - ObserveOnly global transition when all RBACProfiles are provisioned.
//   - Per-namespace enforce transition when namespace profiles are provisioned.
//   - Partial provisioning: global gate remains Initialising; namespace not promoted.
//   - Empty profile list: global gate remains Initialising.
//   - In-memory gate and registry are updated on transitions.
//
// INV-020, CS-INV-004.
package controller_test

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
	"github.com/ontai-dev/guardian/internal/webhook"
)

func buildBootstrapScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(securityv1alpha1.AddToScheme(s))
	return s
}

func buildBootstrapReconciler(t *testing.T, objs ...runtime.Object) (
	*controller.BootstrapController, *webhook.WebhookModeGate, *webhook.NamespaceEnforcementRegistry,
) {
	t.Helper()
	s := buildBootstrapScheme(t)
	builder := fake.NewClientBuilder().WithScheme(s)
	for _, o := range objs {
		builder = builder.WithRuntimeObjects(o)
	}
	c := builder.WithStatusSubresource(&securityv1alpha1.Guardian{}, &securityv1alpha1.RBACProfile{}).Build()
	gate := webhook.NewWebhookModeGate()
	registry := webhook.NewNamespaceEnforcementRegistry()
	r := &controller.BootstrapController{
		Client:            c,
		Scheme:            s,
		Recorder:          record.NewFakeRecorder(32),
		Gate:              gate,
		Registry:          registry,
		OperatorNamespace: controller.GuardianSingletonNamespace,
	}
	return r, gate, registry
}

func reconcileBootstrap(t *testing.T, r *controller.BootstrapController, name, ns string) ctrl.Result {
	t.Helper()
	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: name, Namespace: ns},
	})
	if err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}
	return result
}

func getGuardian(t *testing.T, r *controller.BootstrapController) *securityv1alpha1.Guardian {
	t.Helper()
	gdn := &securityv1alpha1.Guardian{}
	if err := r.Client.Get(context.Background(), types.NamespacedName{
		Name:      controller.GuardianSingletonName,
		Namespace: controller.GuardianSingletonNamespace,
	}, gdn); err != nil {
		t.Fatalf("get Guardian singleton: %v", err)
	}
	return gdn
}

// Test 1 — Startup: Guardian singleton is created with WebhookMode=Initialising.
// First reconcile creates the Guardian CR if absent. INV-020.
func TestBootstrapController_CreatesGuardianSingleton(t *testing.T) {
	r, gate, _ := buildBootstrapReconciler(t)

	// No profiles, no Guardian CR pre-existing.
	reconcileBootstrap(t, r, "any-profile", "seam-system")

	gdn := getGuardian(t, r)
	if gdn.Status.WebhookMode != securityv1alpha1.WebhookModeInitialising {
		t.Errorf("expected WebhookMode=Initialising on creation; got %q", gdn.Status.WebhookMode)
	}

	// In-memory gate must remain Initialising (no profiles → not ready).
	if gate.Mode() != securityv1alpha1.WebhookModeInitialising {
		t.Errorf("expected gate=Initialising; got %q", gate.Mode())
	}
}

// Test 2 — Empty profiles: global gate stays Initialising; Guardian CR created.
// With no RBACProfiles present, there is nothing to check → stay in bootstrap. INV-020.
func TestBootstrapController_NoProfiles_StaysInitialising(t *testing.T) {
	r, gate, _ := buildBootstrapReconciler(t)

	reconcileBootstrap(t, r, "any", "seam-system")

	gdn := getGuardian(t, r)
	if gdn.Status.WebhookMode != securityv1alpha1.WebhookModeInitialising {
		t.Errorf("WebhookMode = %q, want Initialising", gdn.Status.WebhookMode)
	}
	if gate.Mode() != securityv1alpha1.WebhookModeInitialising {
		t.Errorf("gate = %q, want Initialising", gate.Mode())
	}
}

// buildProvisionedProfile creates a provisioned RBACProfile in the given namespace.
func buildProvisionedProfile(name, ns string) *securityv1alpha1.RBACProfile {
	return &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Generation: 1},
		Spec: securityv1alpha1.RBACProfileSpec{
			PrincipalRef:   "test-principal",
			RBACPolicyRef:  "test-policy",
			TargetClusters: []string{"ccs-test"},
			PermissionDeclarations: []securityv1alpha1.PermissionDeclaration{
				{PermissionSetRef: "ps", Scope: securityv1alpha1.PermissionScopeCluster},
			},
		},
		Status: securityv1alpha1.RBACProfileStatus{
			Provisioned: true,
		},
	}
}

// buildUnprovisionedProfile creates an unprovisioned RBACProfile.
func buildUnprovisionedProfile(name, ns string) *securityv1alpha1.RBACProfile {
	p := buildProvisionedProfile(name, ns)
	p.Status.Provisioned = false
	return p
}

// Test 3 — All profiles provisioned: global mode advances to ObserveOnly.
// When all RBACProfiles across all namespaces reach Provisioned=True, the
// BootstrapController sets WebhookMode=ObserveOnly on the Guardian CR and
// advances the in-memory gate. INV-020, CS-INV-004.
func TestBootstrapController_AllProfilesProvisioned_AdvancesToObserveOnly(t *testing.T) {
	p1 := buildProvisionedProfile("profile-guardian", "seam-system")
	p2 := buildProvisionedProfile("profile-platform", "seam-system")
	r, gate, _ := buildBootstrapReconciler(t, p1, p2)

	reconcileBootstrap(t, r, p1.Name, p1.Namespace)

	gdn := getGuardian(t, r)
	if gdn.Status.WebhookMode != securityv1alpha1.WebhookModeObserveOnly {
		t.Errorf("WebhookMode = %q, want ObserveOnly", gdn.Status.WebhookMode)
	}
	if gate.Mode() != securityv1alpha1.WebhookModeObserveOnly {
		t.Errorf("gate = %q, want ObserveOnly", gate.Mode())
	}
}

// Test 4 — Partial provisioning: global mode stays Initialising.
// If any profile is not yet provisioned, the global mode must not advance.
func TestBootstrapController_PartialProvisioning_StaysInitialising(t *testing.T) {
	p1 := buildProvisionedProfile("profile-guardian", "seam-system")
	p2 := buildUnprovisionedProfile("profile-platform", "seam-system")
	r, gate, _ := buildBootstrapReconciler(t, p1, p2)

	reconcileBootstrap(t, r, p1.Name, p1.Namespace)

	gdn := getGuardian(t, r)
	if gdn.Status.WebhookMode != securityv1alpha1.WebhookModeInitialising {
		t.Errorf("WebhookMode = %q, want Initialising (partial provisioning)", gdn.Status.WebhookMode)
	}
	if gate.Mode() != securityv1alpha1.WebhookModeInitialising {
		t.Errorf("gate = %q, want Initialising", gate.Mode())
	}
}

// Test 5 — Per-namespace enforcement: namespace with all profiles provisioned is promoted.
// The BootstrapController records the namespace in Guardian.Status.NamespaceEnforcements
// and marks it active in the in-memory registry. INV-020.
func TestBootstrapController_NamespaceWithAllProfilesProvisioned_IsPromoted(t *testing.T) {
	p1 := buildProvisionedProfile("profile-a", "seam-system")
	r, _, registry := buildBootstrapReconciler(t, p1)

	reconcileBootstrap(t, r, p1.Name, p1.Namespace)

	gdn := getGuardian(t, r)
	if !gdn.Status.NamespaceEnforcements["seam-system"] {
		t.Error("expected seam-system in NamespaceEnforcements after all profiles provisioned")
	}
	if !registry.IsActive("seam-system") {
		t.Error("expected seam-system active in in-memory registry")
	}
}

// Test 6 — Per-namespace enforcement: namespace with unprovisioned profile is NOT promoted.
func TestBootstrapController_NamespaceWithUnprovisionedProfile_NotPromoted(t *testing.T) {
	p1 := buildUnprovisionedProfile("profile-a", "seam-system")
	r, _, registry := buildBootstrapReconciler(t, p1)

	reconcileBootstrap(t, r, p1.Name, p1.Namespace)

	gdn := getGuardian(t, r)
	if gdn.Status.NamespaceEnforcements["seam-system"] {
		t.Error("seam-system must not be in NamespaceEnforcements when profile not provisioned")
	}
	if registry.IsActive("seam-system") {
		t.Error("seam-system must not be active in registry when profile not provisioned")
	}
}

// Test 7 — Mixed namespaces: provisioned namespace promoted; unprovisioned namespace not.
// Two namespaces: seam-system (all provisioned) and ont-system (one unprovisioned).
// Only seam-system should be promoted; global mode stays Initialising (ont-system not ready).
func TestBootstrapController_MixedNamespaces_OnlyProvisionedNamespacePromoted(t *testing.T) {
	p1 := buildProvisionedProfile("guardian-profile", "seam-system")
	p2 := buildUnprovisionedProfile("conductor-profile", "ont-system")
	r, gate, registry := buildBootstrapReconciler(t, p1, p2)

	reconcileBootstrap(t, r, p1.Name, p1.Namespace)

	// seam-system fully provisioned → promoted.
	if !registry.IsActive("seam-system") {
		t.Error("seam-system should be active in registry")
	}
	// ont-system not fully provisioned → not promoted.
	if registry.IsActive("ont-system") {
		t.Error("ont-system must not be active in registry (has unprovisioned profile)")
	}
	// Global gate stays Initialising — not all namespaces ready.
	if gate.Mode() != securityv1alpha1.WebhookModeInitialising {
		t.Errorf("gate = %q, want Initialising (ont-system not ready)", gate.Mode())
	}
}

// Test 8 — ObserveOnly transition is one-way: reconcile after ObserveOnly stays ObserveOnly.
// Once the mode advances to ObserveOnly, BootstrapController must not revert it even
// if a profile becomes unprovisioned (e.g., due to drift). INV-020.
func TestBootstrapController_ObserveOnlyTransitionIsOneWay(t *testing.T) {
	p1 := buildProvisionedProfile("profile-a", "seam-system")
	r, gate, _ := buildBootstrapReconciler(t, p1)

	// First reconcile: advance to ObserveOnly.
	reconcileBootstrap(t, r, p1.Name, p1.Namespace)
	if gate.Mode() != securityv1alpha1.WebhookModeObserveOnly {
		t.Fatalf("precondition: gate should be ObserveOnly after first reconcile")
	}

	// Simulate profile becoming unprovisioned.
	p1.Status.Provisioned = false
	if err := r.Client.Update(context.Background(), p1); err != nil {
		t.Fatalf("update profile: %v", err)
	}

	// Second reconcile: mode must not revert to Initialising.
	reconcileBootstrap(t, r, p1.Name, p1.Namespace)

	gdn := getGuardian(t, r)
	if gdn.Status.WebhookMode != securityv1alpha1.WebhookModeObserveOnly {
		t.Errorf("WebhookMode = %q after revert, want ObserveOnly (one-way ratchet)", gdn.Status.WebhookMode)
	}
	if gate.Mode() != securityv1alpha1.WebhookModeObserveOnly {
		t.Errorf("gate = %q after revert, want ObserveOnly", gate.Mode())
	}
}

// Test 9 — GuardedNamespaceModeResolver: Initialising gate → all non-exempt namespaces observe.
// During bootstrap (gate=Initialising), GuardedNamespaceModeResolver must return Observe
// for any namespace that the base resolver returns Enforce for. INV-020.
func TestGuardedResolver_InitialisingGate_NonExemptNamespacesObserve(t *testing.T) {
	gate := webhook.NewWebhookModeGate() // starts Initialising
	registry := webhook.NewNamespaceEnforcementRegistry()
	base := &webhook.StaticNamespaceModeResolver{
		Modes: map[string]webhook.NamespaceMode{
			"kube-system": webhook.NamespaceModeExempt,
		},
		DefaultMode: webhook.NamespaceModeEnforce,
	}
	resolver := webhook.NewGuardedNamespaceModeResolver(base, gate, registry)

	got := resolver.ResolveMode(context.Background(), "user-namespace")
	if got != webhook.NamespaceModeObserve {
		t.Errorf("Initialising + non-exempt: got %q, want Observe", got)
	}
}

// Test 10 — GuardedNamespaceModeResolver: Initialising gate + exempt namespace → still Exempt.
// Exempt namespaces bypass the global gate — they are always exempt. CS-INV-004.
func TestGuardedResolver_InitialisingGate_ExemptNamespaceRemainsExempt(t *testing.T) {
	gate := webhook.NewWebhookModeGate()
	registry := webhook.NewNamespaceEnforcementRegistry()
	base := &webhook.StaticNamespaceModeResolver{
		Modes: map[string]webhook.NamespaceMode{
			"seam-system": webhook.NamespaceModeExempt,
		},
	}
	resolver := webhook.NewGuardedNamespaceModeResolver(base, gate, registry)

	got := resolver.ResolveMode(context.Background(), "seam-system")
	if got != webhook.NamespaceModeExempt {
		t.Errorf("Initialising + exempt: got %q, want Exempt", got)
	}
}

// Test 11 — GuardedNamespaceModeResolver: ObserveOnly gate + namespace not in registry → Observe.
// After ObserveOnly, namespaces not yet promoted by BootstrapController remain observe. INV-020.
func TestGuardedResolver_ObserveOnlyGate_NamespaceNotInRegistry_Observe(t *testing.T) {
	gate := webhook.NewWebhookModeGate()
	gate.SetMode(securityv1alpha1.WebhookModeObserveOnly)
	registry := webhook.NewNamespaceEnforcementRegistry()
	base := &webhook.StaticNamespaceModeResolver{
		DefaultMode: webhook.NamespaceModeEnforce,
	}
	resolver := webhook.NewGuardedNamespaceModeResolver(base, gate, registry)

	got := resolver.ResolveMode(context.Background(), "not-yet-promoted")
	if got != webhook.NamespaceModeObserve {
		t.Errorf("ObserveOnly + not in registry: got %q, want Observe", got)
	}
}

// Test 12 — GuardedNamespaceModeResolver: ObserveOnly gate + namespace in registry → base mode.
// After the namespace is promoted by BootstrapController (registry.SetActive), the resolver
// returns the base mode — which for a labelled enforce namespace is Enforce. INV-020.
func TestGuardedResolver_ObserveOnlyGate_NamespaceInRegistry_ReturnsBaseMode(t *testing.T) {
	gate := webhook.NewWebhookModeGate()
	gate.SetMode(securityv1alpha1.WebhookModeObserveOnly)
	registry := webhook.NewNamespaceEnforcementRegistry()
	registry.SetActive("promoted-ns")
	base := &webhook.StaticNamespaceModeResolver{
		Modes: map[string]webhook.NamespaceMode{
			"promoted-ns": webhook.NamespaceModeEnforce,
		},
	}
	resolver := webhook.NewGuardedNamespaceModeResolver(base, gate, registry)

	got := resolver.ResolveMode(context.Background(), "promoted-ns")
	if got != webhook.NamespaceModeEnforce {
		t.Errorf("ObserveOnly + in registry: got %q, want Enforce", got)
	}
}
