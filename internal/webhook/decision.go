// Package webhook provides the admission decision logic and server registration
// for the guardian management cluster admission webhook.
//
// This file (decision.go) contains only pure functions and value types. It has
// no imports from sigs.k8s.io/controller-runtime/pkg/webhook, making it safe
// to import by the conductor binary without pulling in server machinery.
// CS-INV-001: the admission webhook is the enforcement mechanism.
package webhook

import "sync/atomic"

// AnnotationRBACOwner is the annotation key that all RBAC resources on the
// management cluster must carry. Any resource arriving at admission without
// this annotation set to AnnotationRBACOwnerValue is rejected. CS-INV-001.
const (
	AnnotationRBACOwner      = "ontai.dev/rbac-owner"
	AnnotationRBACOwnerValue = "guardian"
)

// InterceptedKinds is the set of Kubernetes resource kinds intercepted by the
// ONT RBAC admission webhook on the management cluster. Any resource in this set
// that arrives at admission without the correct ontai.dev/rbac-owner annotation
// is rejected. This matches the ValidatingWebhookConfiguration rules.
var InterceptedKinds = map[string]bool{
	"Role":               true,
	"ClusterRole":        true,
	"RoleBinding":        true,
	"ClusterRoleBinding": true,
	"ServiceAccount":     true,
}

// AdmissionOperation is the type of operation for an incoming admission request.
type AdmissionOperation string

const (
	// OperationCreate represents a resource creation request.
	OperationCreate AdmissionOperation = "CREATE"
	// OperationUpdate represents a resource update request.
	OperationUpdate AdmissionOperation = "UPDATE"
)

// BootstrapWindow tracks whether the bootstrap RBAC window is currently open.
// The window starts open on construction and closes permanently when Close is
// called. All methods are safe for concurrent use from multiple goroutines.
//
// The bootstrap RBAC window exists to allow intercepted RBAC resources through
// admission before guardian's webhook is fully operational. The window closes
// permanently when the webhook is registered. INV-020, CS-INV-004.
type BootstrapWindow struct {
	open atomic.Bool
}

// NewBootstrapWindow returns a BootstrapWindow in the open state.
// The caller must call Close exactly once — when the admission webhook is
// registered and the bootstrap phase is complete. INV-020.
func NewBootstrapWindow() *BootstrapWindow {
	w := &BootstrapWindow{}
	w.open.Store(true)
	return w
}

// IsOpen reports whether the bootstrap RBAC window is currently open.
// Safe for concurrent use.
func (w *BootstrapWindow) IsOpen() bool {
	return w.open.Load()
}

// Close permanently closes the bootstrap RBAC window. After Close returns,
// IsOpen always returns false. Close is idempotent and safe for concurrent use.
// INV-020: the window closes permanently when guardian's admission webhook
// becomes operational.
func (w *BootstrapWindow) Close() {
	w.open.Store(false)
}

// AdmissionRequest is the input to EvaluateAdmission. It contains only the fields
// required for the admission decision, decoupled from any Kubernetes API machinery.
// This type is constructed by rbac_handler.go from the raw admission request,
// keeping the decision logic free of server imports.
type AdmissionRequest struct {
	// Kind is the resource kind being admitted (e.g., "Role", "ClusterRole").
	Kind string
	// Operation is the admission operation type (CREATE or UPDATE).
	Operation AdmissionOperation
	// Annotations are the annotations from the incoming object's metadata.
	// May be nil if the object has no annotations.
	Annotations map[string]string
	// BootstrapWindowOpen is true when the bootstrap RBAC window is open.
	// Set by the admission handler from BootstrapWindow.IsOpen before calling
	// EvaluateAdmission. When true, intercepted RBAC resources are admitted
	// unconditionally to allow guardian's own bootstrap RBAC to land before
	// ownership annotation is applied. INV-020, CS-INV-004.
	BootstrapWindowOpen bool
}

// AdmissionDecision is the result of EvaluateAdmission.
type AdmissionDecision struct {
	// Allowed indicates whether the resource is permitted to proceed.
	Allowed bool
	// Reason is a human-readable explanation of the decision.
	// Empty when Allowed=true.
	Reason string
}

// EvaluateAdmission applies the ONT RBAC ownership policy to an incoming admission
// request. It is a pure function: no side effects, no Kubernetes API calls, no I/O.
//
// Evaluation order:
//  1. If Kind is not in InterceptedKinds, allow unconditionally.
//  2. If the bootstrap RBAC window is open, allow unconditionally. The window is
//     open from guardian startup until the admission webhook is registered.
//     It closes permanently on registration. INV-020, CS-INV-004.
//  3. If annotation ontai.dev/rbac-owner=guardian is present, allow.
//  4. Otherwise, reject with a structured error message.
func EvaluateAdmission(req AdmissionRequest) AdmissionDecision {
	if !InterceptedKinds[req.Kind] {
		return AdmissionDecision{Allowed: true}
	}

	// Bootstrap RBAC window: admit intercepted RBAC resources unconditionally
	// while the window is open. The window is open from guardian startup until
	// the admission webhook server is registered. It then closes permanently.
	// Resources admitted through this window are reconciled by guardian on startup:
	// compliant resources are ownership-annotated; non-compliant are flagged.
	// INV-020, CS-INV-004.
	if req.BootstrapWindowOpen {
		return AdmissionDecision{Allowed: true}
	}

	if req.Annotations[AnnotationRBACOwner] == AnnotationRBACOwnerValue {
		return AdmissionDecision{Allowed: true}
	}

	return AdmissionDecision{
		Allowed: false,
		Reason: "resource must carry annotation ontai.dev/rbac-owner=guardian; " +
			"all RBAC resources on the management cluster are owned exclusively by " +
			"guardian (CS-INV-001)",
	}
}
