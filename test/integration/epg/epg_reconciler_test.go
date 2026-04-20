// Package epg_test contains integration tests for the EPGReconciler.
//
// These tests use envtest to spin up a real API server and etcd. They verify
// the full EPG computation cycle: provisioned RBACProfile → EPG annotation trigger →
// EPGReconciler computation → PermissionSnapshot creation with correct spec and status.
//
// envtest binaries are required. Obtain them with:
//
//	setup-envtest use --bin-dir /tmp/envtest-bins
//
// Set KUBEBUILDER_ASSETS to the path printed by setup-envtest before running.
package epg_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
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
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
)

var (
	cfg       *rest.Config
	k8sClient client.Client
	testEnv   *envtest.Environment
	scheme    = runtime.NewScheme()
)

const (
	testNamespace = "security-system"
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

	// Create the security-system namespace — all test objects live here.
	secNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
	if err := k8sClient.Create(context.Background(), secNS); err != nil {
		panic("failed to create security-system namespace: " + err.Error())
	}

	// Start the manager with all four reconcilers registered.
	// Metrics server is disabled to avoid port conflicts when tests run in parallel.
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
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
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		Recorder:          mgr.GetEventRecorderFor("epg-controller"),
		OperatorNamespace: testNamespace,
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

// poll waits up to timeout for condition to return true, checking every 500ms.
func poll(t *testing.T, timeout time.Duration, condition func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// TestEPG_ProvisionedProfile_CreatesPermissionSnapshot verifies the full EPG path:
// a valid provisioned RBACProfile triggers EPG computation which creates a
// PermissionSnapshot with correct spec and status fields.
func TestEPG_ProvisionedProfile_CreatesPermissionSnapshot(t *testing.T) {
	ns := testNamespace

	// Step 1: Create PermissionSet "read-pods".
	readPods := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{Name: "read-pods", Namespace: ns},
		Spec: securityv1alpha1.PermissionSetSpec{
			Permissions: []securityv1alpha1.PermissionRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []securityv1alpha1.Verb{"get", "list", "watch"},
				},
			},
		},
	}
	if err := k8sClient.Create(context.Background(), readPods); err != nil {
		t.Fatalf("failed to create PermissionSet read-pods: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), readPods) })

	// Step 2: Create RBACPolicy "tenant-policy".
	tenantPolicy := &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-policy", Namespace: ns},
		Spec: securityv1alpha1.RBACPolicySpec{
			SubjectScope:            securityv1alpha1.SubjectScopeTenant,
			EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
			AllowedClusters:         []string{"ccs-test"},
			MaximumPermissionSetRef: "read-pods",
		},
	}
	if err := k8sClient.Create(context.Background(), tenantPolicy); err != nil {
		t.Fatalf("failed to create RBACPolicy tenant-policy: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), tenantPolicy) })

	// Step 3: Wait for policy to be valid.
	ok := poll(t, 10*time.Second, func() bool {
		got := &securityv1alpha1.RBACPolicy{}
		if err := k8sClient.Get(context.Background(),
			types.NamespacedName{Name: "tenant-policy", Namespace: ns}, got); err != nil {
			return false
		}
		c := findCond(got.Status.Conditions, securityv1alpha1.ConditionTypeRBACPolicyValid)
		return c != nil && c.Status == metav1.ConditionTrue
	})
	if !ok {
		t.Fatal("timed out waiting for RBACPolicy tenant-policy to become valid")
	}

	// Step 4: Create RBACProfile "acme-reader".
	acmeReader := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "acme-reader", Namespace: ns},
		Spec: securityv1alpha1.RBACProfileSpec{
			PrincipalRef:   "acme-reader",
			RBACPolicyRef:  "tenant-policy",
			TargetClusters: []string{"ccs-test"},
			PermissionDeclarations: []securityv1alpha1.PermissionDeclaration{
				{
					PermissionSetRef: "read-pods",
					Scope:            securityv1alpha1.PermissionScopeCluster,
					Clusters:         nil, // applies to all TargetClusters
				},
			},
		},
	}
	if err := k8sClient.Create(context.Background(), acmeReader); err != nil {
		t.Fatalf("failed to create RBACProfile acme-reader: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), acmeReader) })

	// Step 5: Wait for acme-reader to be provisioned.
	ok = poll(t, 15*time.Second, func() bool {
		got := &securityv1alpha1.RBACProfile{}
		if err := k8sClient.Get(context.Background(),
			types.NamespacedName{Name: "acme-reader", Namespace: ns}, got); err != nil {
			return false
		}
		return got.Status.Provisioned
	})
	if !ok {
		got := &securityv1alpha1.RBACProfile{}
		_ = k8sClient.Get(context.Background(), types.NamespacedName{Name: "acme-reader", Namespace: ns}, got)
		t.Fatalf("timed out waiting for acme-reader to reach Provisioned=true; conditions: %v",
			got.Status.Conditions)
	}

	// Step 6: Wait for PermissionSnapshot "snapshot-ccs-test" to be created.
	// The RBACProfileReconciler sets the EPG annotation on the profile when it provisioned.
	// The EPGReconciler responds to that annotation and writes the snapshot.
	var snapshot securityv1alpha1.PermissionSnapshot
	ok = poll(t, 20*time.Second, func() bool {
		return k8sClient.Get(context.Background(),
			types.NamespacedName{Name: "snapshot-ccs-test", Namespace: ns},
			&snapshot) == nil
	})
	if !ok {
		// List all snapshots to aid debugging.
		var snapshots securityv1alpha1.PermissionSnapshotList
		_ = k8sClient.List(context.Background(), &snapshots, client.InNamespace(ns))
		t.Fatalf("timed out waiting for PermissionSnapshot snapshot-ccs-test in %s; existing snapshots: %v",
			ns, snapshotNames(snapshots))
	}

	// Assertions on the snapshot spec.
	if snapshot.Spec.TargetCluster != "ccs-test" {
		t.Errorf("Spec.TargetCluster = %q; want %q", snapshot.Spec.TargetCluster, "ccs-test")
	}
	if snapshot.Spec.Version == "" {
		t.Error("Spec.Version should be non-empty (RFC3339 timestamp)")
	}
	if snapshot.Spec.GeneratedAt.IsZero() {
		t.Error("Spec.GeneratedAt should be non-zero")
	}

	// Verify PrincipalPermissions has an entry for acme-reader.
	var principalEntry *securityv1alpha1.PrincipalPermissionEntry
	for i := range snapshot.Spec.PrincipalPermissions {
		if snapshot.Spec.PrincipalPermissions[i].PrincipalRef == "acme-reader" {
			principalEntry = &snapshot.Spec.PrincipalPermissions[i]
			break
		}
	}
	if principalEntry == nil {
		t.Fatalf("expected PrincipalPermissions entry for acme-reader; not found. Entries: %v",
			snapshot.Spec.PrincipalPermissions)
	}

	// Verify pods AllowedOperation is present with get, list, watch.
	var podsOp *securityv1alpha1.AllowedOperation
	for i := range principalEntry.AllowedOperations {
		if principalEntry.AllowedOperations[i].Resource == "pods" {
			podsOp = &principalEntry.AllowedOperations[i]
			break
		}
	}
	if podsOp == nil {
		t.Fatalf("expected AllowedOperation for pods; not found. Operations: %v",
			principalEntry.AllowedOperations)
	}
	verbSet := make(map[string]struct{})
	for _, v := range podsOp.Verbs {
		verbSet[v] = struct{}{}
	}
	for _, expected := range []string{"get", "list", "watch"} {
		if _, ok := verbSet[expected]; !ok {
			t.Errorf("pods AllowedOperation missing verb %q; got verbs: %v", expected, podsOp.Verbs)
		}
	}

	// Wait for the status subresource to be populated.
	ok = poll(t, 10*time.Second, func() bool {
		got := &securityv1alpha1.PermissionSnapshot{}
		if err := k8sClient.Get(context.Background(),
			types.NamespacedName{Name: "snapshot-ccs-test", Namespace: ns}, got); err != nil {
			return false
		}
		return got.Status.ExpectedVersion != ""
	})
	if !ok {
		t.Fatal("timed out waiting for PermissionSnapshot status.ExpectedVersion to be set")
	}

	// Re-fetch with populated status.
	if err := k8sClient.Get(context.Background(),
		types.NamespacedName{Name: "snapshot-ccs-test", Namespace: ns}, &snapshot); err != nil {
		t.Fatalf("failed to re-fetch PermissionSnapshot: %v", err)
	}

	// Status assertions.
	if snapshot.Status.ExpectedVersion != snapshot.Spec.Version {
		t.Errorf("Status.ExpectedVersion = %q; want %q (= Spec.Version)",
			snapshot.Status.ExpectedVersion, snapshot.Spec.Version)
	}
	if !snapshot.Status.Drift {
		t.Error("Status.Drift should be true (delivery has not yet occurred)")
	}
	// LastAckedVersion must NOT be set by the EPGReconciler.
	// (It is owned by the runner agent in agent mode only.)
	// We just verify the overall Drift=true is correct given empty LastAckedVersion.
	if snapshot.Status.LastAckedVersion != "" {
		t.Logf("note: Status.LastAckedVersion=%q (set by external agent, not EPGReconciler)",
			snapshot.Status.LastAckedVersion)
	}
}

// findCond returns the first condition with the given type, or nil.
func findCond(conditions []metav1.Condition, condType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}

// snapshotNames returns a list of snapshot names for debugging.
func snapshotNames(list securityv1alpha1.PermissionSnapshotList) []string {
	names := make([]string, len(list.Items))
	for i, s := range list.Items {
		names[i] = s.Name
	}
	return names
}
