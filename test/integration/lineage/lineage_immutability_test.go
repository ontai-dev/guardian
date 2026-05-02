// Package lineage_test contains integration tests for the guardian
// SealedCausalChain immutability admission webhook.
//
// These tests use envtest to start a real API server, wire the lineage
// immutability webhook, and verify that any attempt to mutate spec.lineage
// after initial object creation is rejected at admission.
//
// The lineage immutability webhook intercepts UPDATE operations on guardian
// root-declaration CRDs (RBACPolicy, RBACProfile, IdentityBinding,
// IdentityProvider, PermissionSet) and rejects requests that modify the
// spec.lineage field. CLAUDE.md §14 Decision 1, seam-core-schema.md §5.
//
// envtest binaries are required:
//
//	setup-envtest use --bin-dir /tmp/envtest-bins
//	export KUBEBUILDER_ASSETS=/tmp/envtest-bins/k8s/1.35.0-linux-amd64
package lineage_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
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
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	seamcorev1alpha1lineage "github.com/ontai-dev/seam-core/pkg/lineage"
	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/webhook"
)

var (
	cfg       *rest.Config
	k8sClient client.Client
	testEnv   *envtest.Environment
	scheme    = runtime.NewScheme()
	ctx       context.Context
	cancel    context.CancelFunc
)

func TestMain(m *testing.M) {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))

	// CRDs are relative to the repository root.
	crdPath := filepath.Join("..", "..", "..", "config", "crd")
	// Lineage webhook config is in this package's testdata directory,
	// separate from the RBAC webhook config so it doesn't affect existing tests.
	webhookPath := filepath.Join("testdata")

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{crdPath},
		ErrorIfCRDPathMissing: true,
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			Paths: []string{webhookPath},
		},
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

	ctx, cancel = context.WithCancel(context.Background())

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false,
		Metrics:        metricsserver.Options{BindAddress: "0"},
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			Port:    testEnv.WebhookInstallOptions.LocalServingPort,
			Host:    testEnv.WebhookInstallOptions.LocalServingHost,
			CertDir: testEnv.WebhookInstallOptions.LocalServingCertDir,
		}),
	})
	if err != nil {
		panic("failed to create manager: " + err.Error())
	}

	// Register the lineage immutability webhook only.
	// The RBAC webhook is NOT registered here — these tests focus solely on
	// the spec.lineage immutability contract.
	webhookServer := webhook.NewAdmissionWebhookServer(mgr)
	webhookServer.RegisterLineage()

	go func() {
		if err := mgr.Start(ctx); err != nil {
			panic("manager failed: " + err.Error())
		}
	}()

	// Wait for the webhook TLS server to become ready.
	waitForWebhookTLS(testEnv.WebhookInstallOptions.LocalServingHost,
		testEnv.WebhookInstallOptions.LocalServingPort)

	// Wait for the webhook to become active by polling until the API server
	// routes lineage UPDATE requests to the local webhook server.
	waitForLineageWebhookActive()

	code := m.Run()
	cancel()
	if err := testEnv.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to stop envtest: %v\n", err)
	}
	os.Exit(code)
}

func waitForWebhookTLS(host string, port int) {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: time.Second}
	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test TLS only
	for i := 0; i < 30; i++ {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	panic("lineage webhook TLS server did not become ready in time")
}

// waitForLineageWebhookActive polls until the lineage webhook intercepts
// an UPDATE on a guardian CRD. Creates a probe PermissionSet, populates
// spec.lineage, then tries to change it — when the webhook is active, this
// change is rejected. Uses the PermissionSet kind as the probe resource.
func waitForLineageWebhookActive() {
	ns := "default"

	probe := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "lineage-probe",
			Namespace: ns,
		},
		Spec: securityv1alpha1.PermissionSetSpec{
			Permissions: []securityv1alpha1.PermissionRule{
				{Resources: []string{"pods"}, Verbs: []securityv1alpha1.Verb{"get"}},
			},
			Lineage: &seamcorev1alpha1lineage.SealedCausalChain{
				RootKind:      "TestRoot",
				RootName:      "probe-root",
				RootNamespace: ns,
				CreatingOperator: seamcorev1alpha1lineage.OperatorIdentity{
					Name:    "guardian",
					Version: "test",
				},
				CreationRationale:        "SecurityEnforcement",
				RootGenerationAtCreation: 1,
			},
		},
	}
	if err := k8sClient.Create(context.Background(), probe); err != nil {
		panic("waitForLineageWebhookActive: create probe: " + err.Error())
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		// Try to patch spec.lineage with a different rootName.
		patch := []byte(`{"spec":{"lineage":{"rootKind":"TestRoot","rootName":"changed-name","rootNamespace":"default","rootUID":"","creatingOperator":{"name":"guardian","version":"test"},"creationRationale":"SecurityEnforcement","rootGenerationAtCreation":1}}}`)
		err := k8sClient.Patch(context.Background(), probe, client.RawPatch(types.MergePatchType, patch))
		if err != nil && isLineageDenial(err) {
			// Webhook is active. Clean up probe.
			_ = k8sClient.Delete(context.Background(), probe)
			return
		}
		if err == nil {
			// Webhook not yet active — update succeeded. Restore and retry.
			restorePatch := []byte(`{"spec":{"lineage":{"rootKind":"TestRoot","rootName":"probe-root","rootNamespace":"default","rootUID":"","creatingOperator":{"name":"guardian","version":"test"},"creationRationale":"SecurityEnforcement","rootGenerationAtCreation":1}}}`)
			_ = k8sClient.Patch(context.Background(), probe, client.RawPatch(types.MergePatchType, restorePatch))
		}
		time.Sleep(500 * time.Millisecond)
	}
	// Clean up probe regardless.
	_ = k8sClient.Delete(context.Background(), probe)
	panic("lineage webhook did not become active within 30 seconds")
}

// --- Tests ---

// TestLineageImmutability_RBACPolicy_UpdateRejected verifies that applying a
// patch that modifies spec.lineage on an existing RBACPolicy is rejected by
// the SealedCausalChain immutability webhook with a clear error.
//
// The sequence:
//  1. Create a RBACPolicy with spec.lineage populated.
//  2. Attempt to PATCH spec.lineage with a different rootName.
//  3. Assert the webhook denies the request.
//  4. Confirm the object's spec.lineage is unchanged in etcd.
//
// Scenario 7 — Test Session F. CLAUDE.md §14 Decision 1.
func TestLineageImmutability_RBACPolicy_UpdateRejected(t *testing.T) {
	ctx := context.Background()
	ns := "default"

	originalLineage := &seamcorev1alpha1lineage.SealedCausalChain{
		RootKind:      "TalosCluster",
		RootName:      "ccs-test",
		RootNamespace: ns,
		CreatingOperator: seamcorev1alpha1lineage.OperatorIdentity{
			Name:    "platform",
			Version: "v1.0.0",
		},
		CreationRationale:        "ClusterProvision",
		RootGenerationAtCreation: 1,
	}

	policy := &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "lineage-immutability-test-policy",
			Namespace: ns,
		},
		Spec: securityv1alpha1.RBACPolicySpec{
			SubjectScope:            securityv1alpha1.SubjectScopePlatform,
			EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
			MaximumPermissionSetRef: "some-ref",
			Lineage:                 originalLineage,
		},
	}
	if err := k8sClient.Create(ctx, policy); err != nil {
		t.Fatalf("Create RBACPolicy with lineage: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, policy) })

	// Attempt to mutate spec.lineage.rootName — the immutability webhook must reject this.
	mutatedLineage := &seamcorev1alpha1lineage.SealedCausalChain{
		RootKind:      "TalosCluster",
		RootName:      "MUTATED-cluster-name", // changed from original
		RootNamespace: ns,
		CreatingOperator: seamcorev1alpha1lineage.OperatorIdentity{
			Name:    "platform",
			Version: "v1.0.0",
		},
		CreationRationale:        "ClusterProvision",
		RootGenerationAtCreation: 1,
	}

	lineageBytes, err := json.Marshal(mutatedLineage)
	if err != nil {
		t.Fatalf("marshal mutated lineage: %v", err)
	}
	patch := append([]byte(`{"spec":{"lineage":`), append(lineageBytes, '}', '}')...)

	patchErr := k8sClient.Patch(ctx, policy,
		client.RawPatch(types.MergePatchType, patch))

	if patchErr == nil {
		t.Fatal("expected lineage immutability webhook to reject spec.lineage mutation; got nil error")
	}
	if !isLineageDenial(patchErr) {
		t.Errorf("expected webhook denial error; got: %v", patchErr)
	}

	// Confirm the object's spec.lineage is unchanged in etcd.
	nn := types.NamespacedName{Name: policy.Name, Namespace: ns}
	got := &securityv1alpha1.RBACPolicy{}
	if err := k8sClient.Get(ctx, nn, got); err != nil {
		t.Fatalf("Get policy after rejected patch: %v", err)
	}
	if got.Spec.Lineage == nil {
		t.Fatal("spec.lineage absent after rejected patch")
	}
	if got.Spec.Lineage.RootName != originalLineage.RootName {
		t.Errorf("spec.lineage.rootName was mutated despite webhook denial: got %q; want %q",
			got.Spec.Lineage.RootName, originalLineage.RootName)
	}
}

// TestLineageImmutability_PermissionSet_UpdateRejected verifies the same
// immutability contract applies to PermissionSet CRDs — the set of intercepted
// kinds includes all five guardian root-declaration CRDs.
// Scenario 7 (additional kind coverage) — Test Session F.
func TestLineageImmutability_PermissionSet_UpdateRejected(t *testing.T) {
	ctx := context.Background()
	ns := "default"

	ps := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "lineage-immutability-test-ps",
			Namespace: ns,
		},
		Spec: securityv1alpha1.PermissionSetSpec{
			Permissions: []securityv1alpha1.PermissionRule{
				{Resources: []string{"pods"}, Verbs: []securityv1alpha1.Verb{"get"}},
			},
			Lineage: &seamcorev1alpha1lineage.SealedCausalChain{
				RootKind:      "RBACPolicy",
				RootName:      "original-policy",
				RootNamespace: ns,
				CreatingOperator: seamcorev1alpha1lineage.OperatorIdentity{
					Name:    "guardian",
					Version: "v1.0.0",
				},
				CreationRationale:        "SecurityEnforcement",
				RootGenerationAtCreation: 1,
			},
		},
	}
	if err := k8sClient.Create(ctx, ps); err != nil {
		t.Fatalf("Create PermissionSet with lineage: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, ps) })

	// Attempt to change spec.lineage.creationRationale — must be rejected.
	patch := []byte(`{"spec":{"lineage":{"rootKind":"RBACPolicy","rootName":"original-policy","rootNamespace":"default","rootUID":"","creatingOperator":{"name":"guardian","version":"v1.0.0"},"creationRationale":"PackExecution","rootGenerationAtCreation":1}}}`)
	patchErr := k8sClient.Patch(ctx, ps, client.RawPatch(types.MergePatchType, patch))
	if patchErr == nil {
		t.Fatal("expected immutability webhook to reject spec.lineage mutation on PermissionSet; got nil")
	}
	if !isLineageDenial(patchErr) {
		t.Errorf("expected webhook denial; got: %v", patchErr)
	}
}

// TestLineageImmutability_CreateWithLineage_Allowed verifies that creating
// a resource WITH spec.lineage is allowed — immutability only applies to
// UPDATE operations that modify the field after creation.
func TestLineageImmutability_CreateWithLineage_Allowed(t *testing.T) {
	ctx := context.Background()
	ns := "default"

	ps := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "lineage-create-allowed",
			Namespace: ns,
		},
		Spec: securityv1alpha1.PermissionSetSpec{
			Permissions: []securityv1alpha1.PermissionRule{
				{Resources: []string{"configmaps"}, Verbs: []securityv1alpha1.Verb{"list"}},
			},
			Lineage: &seamcorev1alpha1lineage.SealedCausalChain{
				RootKind:      "RBACPolicy",
				RootName:      "founding-policy",
				RootNamespace: ns,
				CreatingOperator: seamcorev1alpha1lineage.OperatorIdentity{
					Name:    "guardian",
					Version: "v1.0.0",
				},
				CreationRationale:        "SecurityEnforcement",
				RootGenerationAtCreation: 1,
			},
		},
	}
	if err := k8sClient.Create(ctx, ps); err != nil {
		t.Errorf("expected Create with spec.lineage to be allowed; got: %v", err)
		return
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, ps) })
}

// isLineageDenial returns true if the error indicates a webhook denial from
// the lineage immutability handler.
func isLineageDenial(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, kw := range []string{"denied", "Forbidden", "lineage", "immutable", "sealed", "spec.lineage"} {
		if containsStr(msg, kw) {
			return true
		}
	}
	return false
}

func containsStr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
