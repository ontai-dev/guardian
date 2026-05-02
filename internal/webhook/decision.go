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

// LabelRBACProfileType is the label key that identifies the type of an RBACProfile.
// seam-operator profiles must reference the management-maximum PermissionSet only
// (CS-INV-008). T-25a.
const (
	LabelRBACProfileType            = "ontai.dev/rbac-profile-type"
	LabelRBACProfileTypeSeamOperator = "seam-operator"
)

// managementMaximumPermissionSetRef is the only PermissionSet reference permitted
// in seam-operator RBACProfiles. Any other reference violates CS-INV-008.
const managementMaximumPermissionSetRef = "management-maximum"

// denyReasonSeamOperatorPermissionSetRef is the denial message for seam-operator
// RBACProfiles that reference a PermissionSet other than management-maximum.
const denyReasonSeamOperatorPermissionSetRef = "seam-operator RBACProfiles must reference " +
	"the management-maximum PermissionSet only; per CS-INV-008 no per-component " +
	"PermissionSet is permitted"

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
	"RBACProfile":        true,
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
	// Labels are the labels from the incoming object's metadata.
	// Used for RBACProfile two-path routing (ontai.dev/rbac-profile-type). T-25a.
	// May be nil if the object has no labels.
	Labels map[string]string
	// PermissionSetRefs contains all permissionSetRef values from the admitted
	// RBACProfile's spec.permissionDeclarations. Empty for all other kinds.
	// Used to enforce CS-INV-008 for seam-operator RBACProfiles. T-25a.
	PermissionSetRefs []string
	// BootstrapWindowOpen is true when the bootstrap RBAC window is open.
	// Set by the admission handler from BootstrapWindow.IsOpen before calling
	// EvaluateAdmission. When true, intercepted RBAC resources are admitted
	// unconditionally to allow guardian's own bootstrap RBAC to land before
	// ownership annotation is applied. INV-020, CS-INV-004.
	BootstrapWindowOpen bool
	// NSMode is the admission enforcement tier for the request's namespace,
	// resolved by the NamespaceModeResolver in the handler. The zero value
	// (empty string) is treated as NamespaceModeEnforce — unknown namespaces
	// are governed, not exempted.
	NSMode NamespaceMode
}

// AdmissionDecision is the result of EvaluateAdmission.
type AdmissionDecision struct {
	// Allowed indicates whether the resource is permitted to proceed.
	Allowed bool
	// Reason is a human-readable explanation of the decision.
	// Empty when Allowed=true in Enforce mode.
	// In Observe mode: contains the denial reason that would have been used if
	// the namespace were in Enforce mode. Allowed=true even when Reason is set.
	Reason string
	// ObservedDeny is true when the request is in NamespaceModeObserve and would
	// have been denied in NamespaceModeEnforce. The admission handler logs this
	// as a would-deny observation. Allowed=true regardless when ObservedDeny=true.
	ObservedDeny bool
}

// denyReason is the canonical denial message returned for RBAC resources lacking
// the ownership annotation. Shared by Enforce mode deny and Observe mode would-deny.
const denyReason = "resource must carry annotation ontai.dev/rbac-owner=guardian; " +
	"all RBAC resources on the management cluster are owned exclusively by " +
	"guardian (CS-INV-001)"

// EvaluateAdmission applies the ONT RBAC ownership policy to an incoming admission
// request. It is a pure function: no side effects, no Kubernetes API calls, no I/O.
//
// Evaluation order:
//  1. If NSMode is NamespaceModeExempt: allow immediately without any further
//     evaluation. Applied permanently to seam-system and kube-system.
//  2. If Kind is not in InterceptedKinds: allow unconditionally.
//  3. If the bootstrap RBAC window is open: allow unconditionally. The window is
//     open from guardian startup until the admission webhook is registered.
//     It closes permanently on registration. INV-020, CS-INV-004.
//  4. If annotation ontai.dev/rbac-owner=guardian is present: allow (with RBACProfile
//     seam-operator path additional check: all permissionSetRefs must be
//     management-maximum, CS-INV-008).
//  5. If NSMode is NamespaceModeObserve: allow with ObservedDeny=true and the
//     denial reason recorded. The handler logs the observation.
//  6. Otherwise (Enforce mode or unlabelled namespace): deny.
func EvaluateAdmission(req AdmissionRequest) AdmissionDecision {
	// Gate 1 — Exempt namespace: skip all evaluation.
	// seam-system and kube-system carry this label permanently to prevent
	// guardian's own operator machinery from being blocked at admission.
	if req.NSMode == NamespaceModeExempt {
		return AdmissionDecision{Allowed: true}
	}

	// Gate 2 — Non-intercepted kind: always allow.
	if !InterceptedKinds[req.Kind] {
		return AdmissionDecision{Allowed: true}
	}

	// Gate 3 — Bootstrap RBAC window: admit intercepted RBAC resources
	// unconditionally while the window is open. Resources admitted here are
	// reconciled by guardian on startup. INV-020, CS-INV-004.
	if req.BootstrapWindowOpen {
		return AdmissionDecision{Allowed: true}
	}

	// Gate 4 — Ownership annotation: allow owned resources.
	if req.Annotations[AnnotationRBACOwner] == AnnotationRBACOwnerValue {
		// Gate 4a — RBACProfile seam-operator path: enforce CS-INV-008.
		// Seam-operator profiles must reference management-maximum exclusively.
		// This check applies after ownership is confirmed, ensuring only guardian
		// can author seam-operator profiles, and only with the correct ceiling.
		if req.Kind == "RBACProfile" && req.Labels[LabelRBACProfileType] == LabelRBACProfileTypeSeamOperator {
			if reason := validateSeamOperatorPermissionSetRefs(req.PermissionSetRefs); reason != "" {
				if req.NSMode == NamespaceModeObserve {
					return AdmissionDecision{Allowed: true, ObservedDeny: true, Reason: reason}
				}
				return AdmissionDecision{Allowed: false, Reason: reason}
			}
		}
		return AdmissionDecision{Allowed: true}
	}

	// Gates 5 & 6 — Would-deny point. Behaviour depends on namespace mode.

	// Observe mode: run full evaluation but always return allowed.
	// The handler will log the ObservedDeny observation for monitoring.
	if req.NSMode == NamespaceModeObserve {
		return AdmissionDecision{
			Allowed:      true,
			ObservedDeny: true,
			Reason:       denyReason,
		}
	}

	// Enforce mode (default for unlabelled namespaces — zero value of NSMode).
	return AdmissionDecision{
		Allowed: false,
		Reason:  denyReason,
	}
}

// validateSeamOperatorPermissionSetRefs checks that all PermissionSetRef values
// in a seam-operator RBACProfile are exactly "management-maximum". Returns a
// non-empty denial reason string if any ref violates CS-INV-008, empty if valid.
func validateSeamOperatorPermissionSetRefs(refs []string) string {
	for _, ref := range refs {
		if ref != managementMaximumPermissionSetRef {
			return denyReasonSeamOperatorPermissionSetRef
		}
	}
	return ""
}
