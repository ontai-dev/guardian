// Package webhook provides admission decision logic for the guardian management
// cluster admission webhook.
//
// This file (operator_cr_guard.go) contains only pure functions and value types.
// It has no imports from sigs.k8s.io/controller-runtime/pkg/webhook, making it
// safe to import by the conductor binary without pulling in server machinery.
//
// OPERATOR-AUTHORSHIP GUARD: PackInstance, RunnerConfig, PermissionSnapshot, and
// PackExecution are operator-created CRs. Any UPDATE request on these kinds from
// a principal that is not a seam operator service account
// (system:serviceaccount:seam-system:*) is rejected at admission.
// G-BL-CR-IMMUTABILITY.
package webhook

import (
	"fmt"
	"strings"
)

// OperatorCRGuardWebhookPath is the HTTP path at which the operator CR
// authorship guard webhook is registered. The ValidatingWebhookConfiguration
// clientConfig.service.path must match this value.
const OperatorCRGuardWebhookPath = "/validate-operator-cr"

// ProtectedOperatorCRKinds is the set of operator-created CR kinds that are
// protected from human modification. Any UPDATE request on these kinds from a
// principal that is not a seam operator service account is rejected.
// G-BL-CR-IMMUTABILITY.
var ProtectedOperatorCRKinds = map[string]bool{
	"PackInstance":       true,
	"RunnerConfig":       true,
	"PermissionSnapshot": true,
	"PackExecution":      true,
}

// seamOperatorSAPrefix is the username prefix for seam operator service accounts.
// All operator controllers run as ServiceAccounts in the seam-system namespace.
const seamOperatorSAPrefix = "system:serviceaccount:seam-system:"

// OperatorCRGuardRequest is the input to EvaluateOperatorAuthorship. It contains
// only the fields required for the authorship decision, decoupled from any
// Kubernetes API machinery. Constructed by operator_cr_handler.go from the raw
// admission request.
type OperatorCRGuardRequest struct {
	// Kind is the resource kind being admitted (e.g., "PackInstance").
	Kind string
	// Operation is the admission operation type (CREATE or UPDATE).
	// PATCH operations arrive as UPDATE in the admission webhook.
	Operation AdmissionOperation
	// Username is the requesting principal's username from UserInfo.
	// For Kubernetes service accounts this is system:serviceaccount:ns:name.
	Username string
	// BootstrapWindowOpen is true when the bootstrap RBAC window is open.
	// When true, any principal is permitted to update protected CRs to allow
	// operator machinery to initialise before authorship checks are applied.
	// INV-020.
	BootstrapWindowOpen bool
}

// OperatorCRGuardDecision is the result of EvaluateOperatorAuthorship.
type OperatorCRGuardDecision struct {
	// Allowed indicates whether the request is permitted to proceed.
	Allowed bool
	// Reason is a human-readable explanation of the decision.
	// Empty when Allowed=true.
	Reason string
}

// isSeamOperatorServiceAccount reports whether username belongs to a seam
// operator service account -- a ServiceAccount in seam-system. All operator
// controllers (guardian, wrapper, platform, conductor, seam-core) run as
// ServiceAccounts in seam-system and must be permitted to update protected CRs.
func isSeamOperatorServiceAccount(username string) bool {
	return strings.HasPrefix(username, seamOperatorSAPrefix)
}

// EvaluateOperatorAuthorship applies the operator-authorship guard to an
// incoming admission request. It is a pure function: no side effects, no
// Kubernetes API calls, no I/O.
//
// Evaluation order:
//  1. If Kind is not in ProtectedOperatorCRKinds: allow unconditionally.
//  2. If Operation is not UPDATE: allow unconditionally. Only modifications
//     are guarded -- CREATE requests are not restricted by this guard.
//     In the admission webhook, PATCH arrives as UPDATE.
//  3. If the bootstrap window is open: allow unconditionally. INV-020.
//  4. If Username starts with system:serviceaccount:seam-system:: allow.
//     All seam operator controllers run as ServiceAccounts in seam-system.
//  5. Otherwise: deny with a clear human-readable message.
func EvaluateOperatorAuthorship(req OperatorCRGuardRequest) OperatorCRGuardDecision {
	// Gate 1: unprotected kind.
	if !ProtectedOperatorCRKinds[req.Kind] {
		return OperatorCRGuardDecision{Allowed: true}
	}

	// Gate 2: only UPDATE (and PATCH-as-UPDATE) is guarded.
	if req.Operation != OperationUpdate {
		return OperatorCRGuardDecision{Allowed: true}
	}

	// Gate 3: bootstrap window open -- allow any principal. INV-020.
	if req.BootstrapWindowOpen {
		return OperatorCRGuardDecision{Allowed: true}
	}

	// Gate 4: seam operator service account -- allow.
	if isSeamOperatorServiceAccount(req.Username) {
		return OperatorCRGuardDecision{Allowed: true}
	}

	return OperatorCRGuardDecision{
		Allowed: false,
		Reason: fmt.Sprintf(
			"%s is an operator-created CR and may not be modified by principal %q; "+
				"only seam operator service accounts (system:serviceaccount:seam-system:*) "+
				"may update this resource; if this update is intentional, use the "+
				"operator's reconciliation path to make the change "+
				"(G-BL-CR-IMMUTABILITY)",
			req.Kind, req.Username,
		),
	}
}
