package webhook

import (
	"context"
	"encoding/json"
	"net/http"

	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// RBACAdmissionHandler is a controller-runtime admission.Handler that enforces
// the ONT RBAC ownership annotation policy on the management cluster.
//
// It delegates all admission decisions to EvaluateAdmission in decision.go,
// keeping the policy logic free of controller-runtime server machinery.
// CS-INV-001, CS-INV-006.
type RBACAdmissionHandler struct {
	decoder         *admission.Decoder
	bootstrapWindow *BootstrapWindow
}

// partialObject is used for partial JSON unmarshalling of the admitted resource.
// Only the metadata.annotations field is needed for the admission decision.
type partialObject struct {
	Metadata struct {
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
}

// Handle implements admission.Handler.
// It extracts the resource kind and annotations from the admission request,
// reads the current bootstrap window state, delegates to EvaluateAdmission,
// and returns the appropriate response.
func (h *RBACAdmissionHandler) Handle(_ context.Context, req admission.Request) admission.Response {
	var obj partialObject
	if err := json.Unmarshal(req.Object.Raw, &obj); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	decision := EvaluateAdmission(AdmissionRequest{
		Kind:                req.Kind.Kind,
		Operation:           AdmissionOperation(req.Operation),
		Annotations:         obj.Metadata.Annotations,
		BootstrapWindowOpen: h.bootstrapWindow.IsOpen(),
	})

	if decision.Allowed {
		return admission.Allowed("")
	}
	return admission.Denied(decision.Reason)
}

// InjectDecoder injects the decoder from controller-runtime's webhook builder.
// The decoder is stored but not used for admission decisions — annotations are
// extracted from raw JSON to avoid a dependency on decoded object types.
func (h *RBACAdmissionHandler) InjectDecoder(d *admission.Decoder) error {
	h.decoder = d
	return nil
}
