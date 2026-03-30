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
// WebhookPath ("/validate-rbac"). Must be called after the manager is created and
// before mgr.Start. The manager enforces leader election — the webhook server becomes
// active only after the leader lock is acquired. CS-INV-006.
func (s *AdmissionWebhookServer) Register() error {
	handler := &RBACAdmissionHandler{}
	s.mgr.GetWebhookServer().Register(WebhookPath, &admission.Webhook{Handler: handler})
	return nil
}
