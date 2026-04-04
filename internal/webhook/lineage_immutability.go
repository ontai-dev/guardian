// Package webhook provides admission decision logic for the guardian management
// cluster admission webhook.
//
// This file (lineage_immutability.go) contains only pure functions and value
// types. It has no imports from sigs.k8s.io/controller-runtime/pkg/webhook,
// making it safe to import by the conductor binary without pulling in server
// machinery.
//
// IMMUTABILITY CONTRACT: spec.lineage is authored once at object creation time
// and sealed permanently at that point. This gate rejects any UPDATE request
// that modifies spec.lineage on a guardian root-declaration CRD.
// CLAUDE.md §14 Decision 1, seam-core-schema.md §5.
package webhook

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// LineageWebhookPath is the HTTP path at which the lineage immutability admission
// webhook is registered. The ValidatingWebhookConfiguration clientConfig.service.path
// must match this value.
const LineageWebhookPath = "/validate-lineage"

// InterceptedLineageKinds is the set of guardian root-declaration CRD kinds
// for which spec.lineage immutability is enforced. Any UPDATE to one of these
// kinds that modifies spec.lineage is rejected at admission.
// CLAUDE.md §14 Decision 1.
var InterceptedLineageKinds = map[string]bool{
	"RBACPolicy":       true,
	"RBACProfile":      true,
	"IdentityBinding":  true,
	"IdentityProvider": true,
	"PermissionSet":    true,
}

// LineageImmutabilityRequest is the input to EvaluateLineageImmutability.
// It contains only the fields required for the immutability decision, decoupled
// from any Kubernetes API machinery. Constructed by lineage_handler.go from the
// raw admission request.
type LineageImmutabilityRequest struct {
	// Kind is the resource kind being admitted (e.g., "RBACPolicy").
	Kind string
	// Operation is the admission operation type (CREATE, UPDATE, or other).
	Operation AdmissionOperation
	// OldLineageRaw is the raw JSON bytes of spec.lineage from the existing
	// (old) object. Nil or empty if the field was absent.
	OldLineageRaw []byte
	// NewLineageRaw is the raw JSON bytes of spec.lineage from the incoming
	// (new) object. Nil or empty if the field is absent.
	NewLineageRaw []byte
}

// LineageImmutabilityDecision is the result of EvaluateLineageImmutability.
type LineageImmutabilityDecision struct {
	// Allowed indicates whether the request is permitted to proceed.
	Allowed bool
	// Reason is a human-readable explanation of the decision.
	// Empty when Allowed=true.
	Reason string
}

// EvaluateLineageImmutability applies the spec.lineage immutability policy to
// an incoming admission request. It is a pure function: no side effects, no
// Kubernetes API calls, no I/O.
//
// Evaluation order:
//  1. If Kind is not in InterceptedLineageKinds, allow unconditionally.
//  2. If the operation is not UPDATE (CREATE, DELETE), allow unconditionally.
//     The lineage field is authored at CREATE time. DELETEs are always permitted.
//  3. If the old and new spec.lineage are semantically equal (both absent, or
//     both present and structurally identical), allow.
//  4. Otherwise, reject — spec.lineage has been modified and the mutation is
//     a sealed-field violation. CLAUDE.md §14 Decision 1.
func EvaluateLineageImmutability(req LineageImmutabilityRequest) LineageImmutabilityDecision {
	if !InterceptedLineageKinds[req.Kind] {
		return LineageImmutabilityDecision{Allowed: true}
	}

	// CREATE and DELETE are always allowed. Lineage is authored at CREATE time;
	// deletion does not modify the sealed field.
	if req.Operation != OperationUpdate {
		return LineageImmutabilityDecision{Allowed: true}
	}

	if lineageRawEqual(req.OldLineageRaw, req.NewLineageRaw) {
		return LineageImmutabilityDecision{Allowed: true}
	}

	return LineageImmutabilityDecision{
		Allowed: false,
		Reason: fmt.Sprintf(
			"spec.lineage is immutable after creation and cannot be modified on %s; "+
				"the SealedCausalChain is authored once at object creation time and sealed "+
				"permanently at that point — no controller, human operator, or automation "+
				"pipeline may alter this field post-admission "+
				"(CLAUDE.md §14 Decision 1, seam-core-schema.md §5); "+
				"to record a different causal chain, create a new %s resource",
			req.Kind, req.Kind,
		),
	}
}

// lineageRawEqual reports whether two raw JSON lineage values are semantically
// equal. Both absent (nil or empty) is equal. One absent and one present is not
// equal. Both present: unmarshal both to interface{} and use reflect.DeepEqual
// to compare structural equality regardless of byte-level formatting differences.
func lineageRawEqual(a, b []byte) bool {
	aEmpty := len(a) == 0 || string(a) == "null"
	bEmpty := len(b) == 0 || string(b) == "null"

	if aEmpty && bEmpty {
		return true
	}
	if aEmpty != bEmpty {
		return false
	}

	var va, vb interface{}
	if err := json.Unmarshal(a, &va); err != nil {
		// Treat unmarshal error as not-equal to trigger a rejection.
		return false
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}
