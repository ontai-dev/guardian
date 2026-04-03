// Package webhook_test contains integration tests for the guardian RBAC admission webhook.
//
// These tests use envtest to start a real API server, wire the admission webhook,
// and verify enforcement behavior by attempting to create RBAC resources directly
// through the Kubernetes API.
//
// The webhook enforces: all Role, ClusterRole, RoleBinding, ClusterRoleBinding,
// and ServiceAccount resources on the management cluster must carry the annotation
// ontai.dev/rbac-owner=guardian. CS-INV-001.
//
// kube-system is excluded from enforcement via NamespaceSelector.
//
// envtest binaries are required:
//
//	setup-envtest use --bin-dir /tmp/envtest-bins
//	export KUBEBUILDER_ASSETS=/tmp/envtest-bins/k8s/1.35.0-linux-amd64
package webhook_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

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

	crdPath := filepath.Join("..", "..", "..", "config", "crd")
	webhookPath := filepath.Join("..", "..", "..", "config", "webhook")

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

	// Start the manager with the webhook server bound to the envtest-assigned port.
	ctx, cancel = context.WithCancel(context.Background())

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false,
		// Disable metrics server to avoid port conflicts when tests run in parallel.
		Metrics: metricsserver.Options{BindAddress: "0"},
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			Port:    testEnv.WebhookInstallOptions.LocalServingPort,
			Host:    testEnv.WebhookInstallOptions.LocalServingHost,
			CertDir: testEnv.WebhookInstallOptions.LocalServingCertDir,
		}),
	})
	if err != nil {
		panic("failed to create manager: " + err.Error())
	}

	// Register the RBAC admission webhook. The bootstrap window is created open
	// and permanently closed inside Register() — by the time the webhook server
	// begins serving, the window is closed and normal annotation enforcement applies.
	// INV-020, CS-INV-004.
	bootstrapWindow := webhook.NewBootstrapWindow()
	webhookServer := webhook.NewAdmissionWebhookServer(mgr)
	if err := webhookServer.Register(bootstrapWindow); err != nil {
		panic("failed to register admission webhook: " + err.Error())
	}

	go func() {
		if err := mgr.Start(ctx); err != nil {
			panic("manager failed: " + err.Error())
		}
	}()

	// Wait for the webhook server to accept TLS connections.
	waitForWebhookTLS(testEnv.WebhookInstallOptions.LocalServingHost,
		testEnv.WebhookInstallOptions.LocalServingPort)

	// Wait for the webhook to become active — the API server may take time to load
	// the webhook config and start routing requests to the local server.
	// This is the same pattern used by controller-runtime's own webhook integration tests.
	waitForWebhookActive()

	code := m.Run()

	cancel()
	if err := testEnv.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to stop envtest: %v\n", err)
	}
	os.Exit(code)
}

// waitForWebhookTLS polls the webhook server TLS endpoint until it accepts connections.
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
	panic("webhook TLS server did not become ready in time")
}

// waitForWebhookActive polls until the webhook actually intercepts and denies
// a Role create without the ownership annotation. This confirms the API server
// has loaded the ValidatingWebhookConfiguration and is routing to the local server.
// The controller-runtime envtest webhook tests use the same eventual-consistency approach.
func waitForWebhookActive() {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "webhook-probe"}}
	_ = k8sClient.Create(context.Background(), ns)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		probe := &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "webhook-probe-role",
				Namespace: "webhook-probe",
			},
			Rules: []rbacv1.PolicyRule{},
		}
		err := k8sClient.Create(context.Background(), probe)
		if err != nil && isWebhookDenial(err) {
			// Webhook is active. Clean up and return.
			return
		}
		if err == nil {
			// Request was allowed — webhook not yet active. Clean up and retry.
			_ = k8sClient.Delete(context.Background(), probe)
		}
		time.Sleep(500 * time.Millisecond)
	}
	panic("webhook did not become active within 30 seconds")
}

// --- Test helpers ---

func roleWithAnnotation(ns, name string, annotations map[string]string) *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Annotations: annotations,
		},
		Rules: []rbacv1.PolicyRule{},
	}
}

func clusterRoleWithAnnotation(name string, annotations map[string]string) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
		},
		Rules: []rbacv1.PolicyRule{},
	}
}

func serviceAccountWithAnnotation(ns, name string, annotations map[string]string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Annotations: annotations,
		},
	}
}

func ownedAnnotation() map[string]string {
	return map[string]string{
		webhook.AnnotationRBACOwner: webhook.AnnotationRBACOwnerValue,
	}
}

// ensureNamespace creates a namespace if it does not already exist.
func ensureNamespace(t *testing.T, name string) {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	err := k8sClient.Create(ctx, ns)
	if err != nil && client.IgnoreAlreadyExists(err) != nil {
		t.Fatalf("failed to create namespace %q: %v", name, err)
	}
}

// --- Integration Tests ---

// Test 1 — Role CREATE without annotation in a user namespace: denied.
// The management cluster webhook rejects RBAC resources without ownership annotation.
func TestWebhook_Role_NoAnnotation_Denied(t *testing.T) {
	ensureNamespace(t, "security-system")
	role := roleWithAnnotation("security-system", "test-role-no-ann", nil)
	err := k8sClient.Create(ctx, role)
	if err == nil {
		t.Error("expected error for Role without annotation; got nil")
		_ = k8sClient.Delete(ctx, role)
		return
	}
	if !isWebhookDenial(err) {
		t.Errorf("expected webhook denial; got %v", err)
	}
}

// Test 2 — Role CREATE with correct annotation: allowed.
func TestWebhook_Role_CorrectAnnotation_Allowed(t *testing.T) {
	ensureNamespace(t, "security-system")
	role := roleWithAnnotation("security-system", "test-role-owned", ownedAnnotation())
	if err := k8sClient.Create(ctx, role); err != nil {
		t.Errorf("expected Role with correct annotation to be allowed; got %v", err)
		return
	}
	_ = k8sClient.Delete(ctx, role)
}

// Test 3 — ClusterRole CREATE without annotation: denied.
func TestWebhook_ClusterRole_NoAnnotation_Denied(t *testing.T) {
	cr := clusterRoleWithAnnotation("test-clusterrole-no-ann", nil)
	err := k8sClient.Create(ctx, cr)
	if err == nil {
		t.Error("expected error for ClusterRole without annotation; got nil")
		_ = k8sClient.Delete(ctx, cr)
		return
	}
	if !isWebhookDenial(err) {
		t.Errorf("expected webhook denial; got %v", err)
	}
}

// Test 4 — ServiceAccount CREATE without annotation: denied.
func TestWebhook_ServiceAccount_NoAnnotation_Denied(t *testing.T) {
	ensureNamespace(t, "security-system")
	sa := serviceAccountWithAnnotation("security-system", "test-sa-no-ann", nil)
	err := k8sClient.Create(ctx, sa)
	if err == nil {
		t.Error("expected error for ServiceAccount without annotation; got nil")
		_ = k8sClient.Delete(ctx, sa)
		return
	}
	if !isWebhookDenial(err) {
		t.Errorf("expected webhook denial; got %v", err)
	}
}

// Test 5 — ServiceAccount CREATE with correct annotation: allowed.
func TestWebhook_ServiceAccount_CorrectAnnotation_Allowed(t *testing.T) {
	ensureNamespace(t, "security-system")
	sa := serviceAccountWithAnnotation("security-system", "test-sa-owned", ownedAnnotation())
	if err := k8sClient.Create(ctx, sa); err != nil {
		t.Errorf("expected ServiceAccount with correct annotation to be allowed; got %v", err)
		return
	}
	_ = k8sClient.Delete(ctx, sa)
}

// Test 6 — Role CREATE in kube-system without annotation: allowed.
// kube-system is excluded from webhook enforcement via NamespaceSelector.
func TestWebhook_KubeSystem_Role_NoAnnotation_Allowed(t *testing.T) {
	role := roleWithAnnotation("kube-system", "test-kubesys-role", nil)
	if err := k8sClient.Create(ctx, role); err != nil {
		t.Errorf("expected Role in kube-system to be allowed (excluded namespace); got %v", err)
		return
	}
	_ = k8sClient.Delete(ctx, role)
}

// Test 7 — ConfigMap CREATE without annotation: allowed.
// ConfigMap is not an intercepted resource kind. The webhook does not apply.
func TestWebhook_ConfigMap_NoAnnotation_Allowed(t *testing.T) {
	ensureNamespace(t, "security-system")
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cm-no-ann",
			Namespace: "security-system",
		},
	}
	if err := k8sClient.Create(ctx, cm); err != nil {
		t.Errorf("expected ConfigMap without annotation to be allowed; got %v", err)
		return
	}
	_ = k8sClient.Delete(ctx, cm)
}

// isWebhookDenial returns true if the error is a webhook-denied admission error.
// The Kubernetes API server returns a status error for admission webhook denials.
func isWebhookDenial(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "denied") || contains(msg, "Forbidden") || contains(msg, "CS-INV-001") || contains(msg, "rbac-owner")
}

func contains(s, sub string) bool {
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
