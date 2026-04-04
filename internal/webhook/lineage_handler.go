package webhook

import (
	"context"
	"encoding/json"
	"net/http"

	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// LineageImmutabilityHandler is a controller-runtime admission.Handler that
// enforces spec.lineage immutability on guardian root-declaration CRDs.
//
// It intercepts UPDATE requests for RBACPolicy, RBACProfile, IdentityBinding,
// IdentityProvider, and PermissionSet. If the incoming object's spec.lineage
// differs from the existing object's spec.lineage, the request is rejected.
// CREATE and DELETE are always permitted.
//
// Decision logic is delegated to EvaluateLineageImmutability in
// lineage_immutability.go, keeping policy logic free of controller-runtime
// server machinery. CLAUDE.md §14 Decision 1.
type LineageImmutabilityHandler struct {
	decoder *admission.Decoder
}

// specLineageExtract is used for partial JSON unmarshalling of admitted resources.
// Only the spec.lineage field is needed for the immutability decision.
type specLineageExtract struct {
	Spec struct {
		Lineage *json.RawMessage `json:"lineage"`
	} `json:"spec"`
}

// Handle implements admission.Handler.
// It extracts spec.lineage from both the incoming (new) and existing (old) object,
// delegates to EvaluateLineageImmutability, and returns the appropriate response.
func (h *LineageImmutabilityHandler) Handle(_ context.Context, req admission.Request) admission.Response {
	newLineage, err := extractSpecLineage(req.Object.Raw)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	oldLineage, err := extractSpecLineage(req.OldObject.Raw)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	var oldBytes, newBytes []byte
	if oldLineage != nil {
		oldBytes = []byte(*oldLineage)
	}
	if newLineage != nil {
		newBytes = []byte(*newLineage)
	}

	decision := EvaluateLineageImmutability(LineageImmutabilityRequest{
		Kind:          req.Kind.Kind,
		Operation:     AdmissionOperation(req.Operation),
		OldLineageRaw: oldBytes,
		NewLineageRaw: newBytes,
	})

	if decision.Allowed {
		return admission.Allowed("")
	}
	return admission.Denied(decision.Reason)
}

// InjectDecoder injects the decoder from controller-runtime's webhook builder.
// Stored but not used for admission decisions — spec.lineage is extracted from
// raw JSON to avoid a dependency on decoded object types.
func (h *LineageImmutabilityHandler) InjectDecoder(d *admission.Decoder) error {
	h.decoder = d
	return nil
}

// extractSpecLineage extracts the spec.lineage field as a raw JSON value from
// the provided raw object bytes. Returns nil if the field is absent or if raw
// is empty. Returns an error only on malformed JSON.
func extractSpecLineage(raw []byte) (*json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var obj specLineageExtract
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	return obj.Spec.Lineage, nil
}
