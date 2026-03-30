// Package webhook provides the admission decision logic and server registration
// for the ont-security management cluster admission webhook.
//
// This file (decision.go) contains only pure functions and value types. It has
// no imports from sigs.k8s.io/controller-runtime/pkg/webhook, making it safe
// to import by the ont-agent binary without pulling in server machinery.
// CS-INV-001: the admission webhook is the enforcement mechanism.
package webhook

// AnnotationRBACOwner is the annotation key that all RBAC resources on the
// management cluster must carry. Any resource arriving at admission without
// this annotation set to AnnotationRBACOwnerValue is rejected. CS-INV-001.
const (
	AnnotationRBACOwner      = "ontai.dev/rbac-owner"
	AnnotationRBACOwnerValue = "ont-security"
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

// AdmissionRequest is the input to EvaluateAdmission. It contains only the fields
// required for the admission decision, decoupled from any Kubernetes API machinery.
// This type is designed to be constructed by rbac_handler.go from the raw admission
// request, keeping the decision logic free of server imports.
type AdmissionRequest struct {
	// Kind is the resource kind being admitted (e.g., "Role", "ClusterRole").
	Kind string
	// Operation is the admission operation type (CREATE or UPDATE).
	Operation AdmissionOperation
	// Annotations are the annotations from the incoming object's metadata.
	// May be nil if the object has no annotations.
	Annotations map[string]string
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
//  2. TODO(session-8): bootstrap RBAC window check — if the window is open and the
//     resource matches the bootstrap RBACPolicy, allow it and continue. The window
//     closes permanently when ont-security's webhook becomes operational.
//     INV-020, CS-INV-004. Bootstrap window state must be thread-safe.
//  3. If annotation ontai.dev/rbac-owner=ont-security is present, allow.
//  4. Otherwise, reject with a structured error message.
func EvaluateAdmission(req AdmissionRequest) AdmissionDecision {
	if !InterceptedKinds[req.Kind] {
		return AdmissionDecision{Allowed: true}
	}

	// TODO(session-8): evaluate bootstrap RBAC window. If the window is open and this
	// resource matches the bootstrap RBACPolicy, allow it and continue. The window
	// closes permanently once ont-security's admission webhook becomes operational.
	// INV-020, CS-INV-004. Bootstrap window state must be thread-safe (accessed from
	// the HTTP handler goroutine pool). This stub is intentionally left unimplemented;
	// the window is treated as permanently closed until Session 8.

	if req.Annotations[AnnotationRBACOwner] == AnnotationRBACOwnerValue {
		return AdmissionDecision{Allowed: true}
	}

	return AdmissionDecision{
		Allowed: false,
		Reason: "resource must carry annotation ontai.dev/rbac-owner=ont-security; " +
			"all RBAC resources on the management cluster are owned exclusively by " +
			"ont-security (CS-INV-001)",
	}
}
