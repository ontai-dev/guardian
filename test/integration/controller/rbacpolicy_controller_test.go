// Package controller_test contains integration tests for the RBACPolicyReconciler.
//
// These tests use envtest to spin up a real API server and etcd, verifying
// that the reconciler correctly sets status conditions in response to valid
// and invalid RBACPolicy specs.
//
// envtest binaries are required. Obtain them with:
//
//	setup-envtest use --bin-dir /tmp/envtest-bins
//
// Set KUBEBUILDER_ASSETS to the path printed by setup-envtest before running.
package controller_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	securityv1alpha1 "github.com/ontai-dev/ont-security/api/v1alpha1"
	"github.com/ontai-dev/ont-security/internal/controller"
)

var (
	cfg       *rest.Config
	k8sClient client.Client
	testEnv   *envtest.Environment
	scheme    = runtime.NewScheme()
)

func TestMain(m *testing.M) {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))

	// CRD YAML is relative to the repository root.
	crdPath := filepath.Join("..", "..", "..", "config", "crd")

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{crdPath},
		ErrorIfCRDPathMissing: true,
	}

	var err error
	cfg, err = testEnv.Start()
	if err != nil {
		panic("failed to start envtest: " + err.Error())
	}

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		panic("failed to create client: " + err.Error())
	}

	// Start the reconcilers in a background manager.
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
	})
	if err != nil {
		panic("failed to create manager: " + err.Error())
	}
	if err := (&controller.RBACPolicyReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("rbacpolicy-controller"),
	}).SetupWithManager(mgr); err != nil {
		panic("failed to register RBACPolicyReconciler: " + err.Error())
	}
	if err := (&controller.RBACProfileReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("rbacprofile-controller"),
	}).SetupWithManager(mgr); err != nil {
		panic("failed to register RBACProfileReconciler: " + err.Error())
	}
	if err := (&controller.IdentityBindingReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("identitybinding-controller"),
	}).SetupWithManager(mgr); err != nil {
		panic("failed to register IdentityBindingReconciler: " + err.Error())
	}
	if err := (&controller.EPGReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("epg-controller"),
	}).SetupWithManager(mgr); err != nil {
		panic("failed to register EPGReconciler: " + err.Error())
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := mgr.Start(ctx); err != nil {
			panic("manager exited with error: " + err.Error())
		}
	}()

	code := m.Run()
	cancel()
	_ = testEnv.Stop()
	os.Exit(code)
}

// poll waits up to timeout for condition to return true, checking every 200ms.
func poll(t *testing.T, timeout time.Duration, condition func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// makePolicy creates a RBACPolicy in the given namespace and registers cleanup.
func makePolicy(t *testing.T, name, namespace string, spec securityv1alpha1.RBACPolicySpec) *securityv1alpha1.RBACPolicy {
	t.Helper()
	p := &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       spec,
	}
	if err := k8sClient.Create(context.Background(), p); err != nil {
		t.Fatalf("failed to create RBACPolicy %s/%s: %v", namespace, name, err)
	}
	t.Cleanup(func() {
		_ = k8sClient.Delete(context.Background(), p)
	})
	return p
}

// TestReconciler_ValidPolicySetsValidConditionTrue verifies that a structurally
// valid RBACPolicy ends up with RBACPolicyValid=True after reconciliation.
// The PermissionSet referenced by MaximumPermissionSetRef must exist — this is
// enforced by the existence check added in Session 4.
func TestReconciler_ValidPolicySetsValidConditionTrue(t *testing.T) {
	ns := "default"
	// Create the PermissionSet first so the policy reconciler finds it.
	ps := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{Name: "platform-max", Namespace: ns},
		Spec: securityv1alpha1.PermissionSetSpec{
			Permissions: []securityv1alpha1.PermissionRule{
				{Resources: []string{"pods"}, Verbs: []string{"get"}},
			},
		},
	}
	if err := k8sClient.Create(context.Background(), ps); err != nil {
		t.Fatalf("failed to create PermissionSet: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), ps) })

	policy := makePolicy(t, "valid-policy", ns, securityv1alpha1.RBACPolicySpec{
		SubjectScope:            securityv1alpha1.SubjectScopePlatform,
		EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
		AllowedClusters:         []string{"ccs-dev"},
		MaximumPermissionSetRef: "platform-max",
	})

	nn := types.NamespacedName{Name: policy.Name, Namespace: ns}
	ok := poll(t, 10*time.Second, func() bool {
		got := &securityv1alpha1.RBACPolicy{}
		if err := k8sClient.Get(context.Background(), nn, got); err != nil {
			return false
		}
		c := findCond(got.Status.Conditions, securityv1alpha1.ConditionTypeRBACPolicyValid)
		return c != nil && c.Status == metav1.ConditionTrue
	})
	if !ok {
		t.Error("timed out waiting for RBACPolicyValid=True")
	}
}

// TestReconciler_ValidPolicySetsNotDegraded verifies that a valid policy also
// ends up with RBACPolicyDegraded=False.
func TestReconciler_ValidPolicySetsNotDegraded(t *testing.T) {
	ns := "default"
	// Create the PermissionSet first (Session 4: existence check now required).
	ps := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-max", Namespace: ns},
		Spec: securityv1alpha1.PermissionSetSpec{
			Permissions: []securityv1alpha1.PermissionRule{
				{Resources: []string{"configmaps"}, Verbs: []string{"get", "list"}},
			},
		},
	}
	if err := k8sClient.Create(context.Background(), ps); err != nil {
		t.Fatalf("failed to create PermissionSet: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), ps) })

	policy := makePolicy(t, "valid-not-degraded", ns, securityv1alpha1.RBACPolicySpec{
		SubjectScope:            securityv1alpha1.SubjectScopeTenant,
		EnforcementMode:         securityv1alpha1.EnforcementModeAudit,
		AllowedClusters:         []string{},
		MaximumPermissionSetRef: "tenant-max",
	})

	nn := types.NamespacedName{Name: policy.Name, Namespace: ns}
	ok := poll(t, 10*time.Second, func() bool {
		got := &securityv1alpha1.RBACPolicy{}
		if err := k8sClient.Get(context.Background(), nn, got); err != nil {
			return false
		}
		c := findCond(got.Status.Conditions, securityv1alpha1.ConditionTypeRBACPolicyDegraded)
		return c != nil && c.Status == metav1.ConditionFalse
	})
	if !ok {
		t.Error("timed out waiting for RBACPolicyDegraded=False")
	}
}

// TestReconciler_InvalidPolicySetsValidConditionFalse verifies that an invalid
// RBACPolicy ends up with RBACPolicyValid=False after reconciliation.
//
// Note: invalid enum values for subjectScope and enforcementMode are rejected by
// the CRD schema at admission before the reconciler runs. This test uses an
// AllowedClusters entry containing whitespace, which passes CRD schema validation
// but fails ValidateRBACPolicySpec check 3 (CheckAllowedClustersFormat).
func TestReconciler_InvalidPolicySetsValidConditionFalse(t *testing.T) {
	ns := "default"
	// AllowedClusters contains whitespace — passes CRD enum checks, fails in-process validation.
	policy := makePolicy(t, "invalid-cluster-name", ns, securityv1alpha1.RBACPolicySpec{
		SubjectScope:            securityv1alpha1.SubjectScopePlatform,
		EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
		AllowedClusters:         []string{"bad cluster"},
		MaximumPermissionSetRef: "some-ref",
	})

	nn := types.NamespacedName{Name: policy.Name, Namespace: ns}
	ok := poll(t, 10*time.Second, func() bool {
		got := &securityv1alpha1.RBACPolicy{}
		if err := k8sClient.Get(context.Background(), nn, got); err != nil {
			return false
		}
		c := findCond(got.Status.Conditions, securityv1alpha1.ConditionTypeRBACPolicyValid)
		return c != nil && c.Status == metav1.ConditionFalse
	})
	if !ok {
		got := &securityv1alpha1.RBACPolicy{}
		_ = k8sClient.Get(context.Background(), nn, got)
		t.Errorf("timed out waiting for RBACPolicyValid=False; conditions: %v", got.Status.Conditions)
	}
}

// TestReconciler_InvalidPolicySetsDegraded verifies that an invalid policy also
// ends up with RBACPolicyDegraded=True.
func TestReconciler_InvalidPolicySetsDegraded(t *testing.T) {
	ns := "default"
	policy := makePolicy(t, "invalid-degraded", ns, securityv1alpha1.RBACPolicySpec{
		SubjectScope:            securityv1alpha1.SubjectScopePlatform,
		EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
		AllowedClusters:         []string{},
		MaximumPermissionSetRef: "", // empty — check 4 fails
	})

	nn := types.NamespacedName{Name: policy.Name, Namespace: ns}
	ok := poll(t, 10*time.Second, func() bool {
		got := &securityv1alpha1.RBACPolicy{}
		if err := k8sClient.Get(context.Background(), nn, got); err != nil {
			return false
		}
		c := findCond(got.Status.Conditions, securityv1alpha1.ConditionTypeRBACPolicyDegraded)
		return c != nil && c.Status == metav1.ConditionTrue
	})
	if !ok {
		t.Error("timed out waiting for RBACPolicyDegraded=True")
	}
}

// TestReconciler_ObservedGenerationAdvances verifies that after reconciliation
// the status ObservedGeneration matches the spec Generation.
func TestReconciler_ObservedGenerationAdvances(t *testing.T) {
	ns := "default"
	policy := makePolicy(t, "observed-gen", ns, securityv1alpha1.RBACPolicySpec{
		SubjectScope:            securityv1alpha1.SubjectScopePlatform,
		EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
		AllowedClusters:         []string{},
		MaximumPermissionSetRef: "platform-max",
	})

	nn := types.NamespacedName{Name: policy.Name, Namespace: ns}
	ok := poll(t, 10*time.Second, func() bool {
		got := &securityv1alpha1.RBACPolicy{}
		if err := k8sClient.Get(context.Background(), nn, got); err != nil {
			return false
		}
		return got.Status.ObservedGeneration == got.Generation
	})
	if !ok {
		t.Error("timed out waiting for ObservedGeneration to match Generation")
	}
}

// TestReconciler_MissingPermissionSetCausesNotFound verifies that a valid RBACPolicy
// whose MaximumPermissionSetRef references a non-existent PermissionSet reaches
// RBACPolicyValid=False with reason=PermissionSetNotFound. When the PermissionSet
// is subsequently created, the next reconcile (triggered by the 30s requeue) sets
// RBACPolicyValid=True.
func TestReconciler_MissingPermissionSetCausesNotFound(t *testing.T) {
	ns := "default"
	// Create a structurally valid policy referencing a nonexistent PermissionSet.
	policy := makePolicy(t, "missing-permset", ns, securityv1alpha1.RBACPolicySpec{
		SubjectScope:            securityv1alpha1.SubjectScopeTenant,
		EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
		AllowedClusters:         []string{"ccs-test"},
		MaximumPermissionSetRef: "nonexistent-set",
	})

	nn := types.NamespacedName{Name: policy.Name, Namespace: ns}

	// Step 1: wait for PermissionSetNotFound condition.
	ok := poll(t, 10*time.Second, func() bool {
		got := &securityv1alpha1.RBACPolicy{}
		if err := k8sClient.Get(context.Background(), nn, got); err != nil {
			return false
		}
		c := findCond(got.Status.Conditions, securityv1alpha1.ConditionTypeRBACPolicyValid)
		return c != nil &&
			c.Status == metav1.ConditionFalse &&
			c.Reason == securityv1alpha1.ReasonPermissionSetNotFound
	})
	if !ok {
		got := &securityv1alpha1.RBACPolicy{}
		_ = k8sClient.Get(context.Background(), nn, got)
		t.Fatalf("timed out waiting for PermissionSetNotFound condition; conditions: %v", got.Status.Conditions)
	}

	// Step 2: create the PermissionSet.
	ps := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{Name: "nonexistent-set", Namespace: ns},
		Spec: securityv1alpha1.PermissionSetSpec{
			Permissions: []securityv1alpha1.PermissionRule{
				{Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
			},
		},
	}
	if err := k8sClient.Create(context.Background(), ps); err != nil {
		t.Fatalf("failed to create PermissionSet: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), ps) })

	// Step 3: wait up to 40 seconds for the next reconcile (30s requeue ceiling)
	// to pick up the newly created PermissionSet and set RBACPolicyValid=True.
	ok = poll(t, 40*time.Second, func() bool {
		got := &securityv1alpha1.RBACPolicy{}
		if err := k8sClient.Get(context.Background(), nn, got); err != nil {
			return false
		}
		c := findCond(got.Status.Conditions, securityv1alpha1.ConditionTypeRBACPolicyValid)
		return c != nil && c.Status == metav1.ConditionTrue
	})
	if !ok {
		got := &securityv1alpha1.RBACPolicy{}
		_ = k8sClient.Get(context.Background(), nn, got)
		t.Errorf("timed out waiting for RBACPolicyValid=True after PermissionSet created; conditions: %v", got.Status.Conditions)
	}
}

// findCond is a test helper that finds a condition by type in a slice.
func findCond(conditions []metav1.Condition, condType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}
