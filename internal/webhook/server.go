package webhook

import (
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// WebhookPath is the HTTP path at which the RBAC admission webhook is registered.
// The ValidatingWebhookConfiguration clientConfig.service.path must match this value.
const WebhookPath = "/validate-rbac"

// AdmissionWebhookServer wraps the controller-runtime manager and exposes a single
// Register method to wire the RBAC admission webhook into the manager's webhook server.
// CS-INV-001: admission webhook is the enforcement mechanism.
// CS-INV-006: leader election is enforced by the manager; the webhook server starts
// only after the leader lock is acquired.
type AdmissionWebhookServer struct {
	mgr ctrl.Manager
}

// NewAdmissionWebhookServer creates a new AdmissionWebhookServer bound to mgr.
func NewAdmissionWebhookServer(mgr ctrl.Manager) *AdmissionWebhookServer {
	return &AdmissionWebhookServer{mgr: mgr}
}

// Register wires the RBACAdmissionHandler into the manager's webhook server at
// WebhookPath ("/validate-rbac") and permanently closes the bootstrap RBAC window.
//
// The handler is constructed with the provided window and namespaceMode resolver.
// The namespace mode resolver is called on each incoming request to determine the
// per-namespace enforcement tier (exempt/observe/enforce) before policy evaluation.
//
// The window is read on each incoming admission request to determine bootstrap
// window state. After the handler is registered, the window is closed — from this
// point forward all intercepted RBAC resources must carry the
// ontai.dev/rbac-owner=guardian annotation.
//
// Register must be called after the manager is created and before mgr.Start.
// The manager enforces leader election — the webhook server becomes active only
// after the leader lock is acquired. CS-INV-006.
//
// INV-020: the bootstrap RBAC window closes permanently when the admission webhook
// becomes operational. The close happens here, on first successful registration.
func (s *AdmissionWebhookServer) Register(window *BootstrapWindow, namespaceMode NamespaceModeResolver) error {
	handler := &RBACAdmissionHandler{
		bootstrapWindow: window,
		namespaceMode:   namespaceMode,
	}
	s.mgr.GetWebhookServer().Register(WebhookPath, &admission.Webhook{Handler: handler})
	// Close the bootstrap RBAC window. The webhook handler is now registered and
	// will begin enforcing the ownership annotation on all intercepted RBAC
	// resources once the manager starts. INV-020, CS-INV-004.
	window.Close()
	return nil
}

// RegisterLineage wires the LineageImmutabilityHandler into the manager's webhook
// server at LineageWebhookPath ("/validate-lineage").
//
// The handler enforces spec.lineage immutability on guardian root-declaration CRDs
// (RBACPolicy, RBACProfile, IdentityBinding, IdentityProvider, PermissionSet).
// Any UPDATE request that modifies spec.lineage is rejected at admission.
// CLAUDE.md §14 Decision 1, seam-core-schema.md §5.
//
// RegisterLineage must be called after the manager is created and before mgr.Start,
// alongside Register. CS-INV-006.
func (s *AdmissionWebhookServer) RegisterLineage() {
	handler := &LineageImmutabilityHandler{}
	s.mgr.GetWebhookServer().Register(LineageWebhookPath, &admission.Webhook{Handler: handler})
}
