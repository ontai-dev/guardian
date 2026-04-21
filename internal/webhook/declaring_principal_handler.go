package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// DeclaringPrincipalWebhookPath is the HTTP path for the declaring-principal
// mutating webhook.
const DeclaringPrincipalWebhookPath = "/mutate-declaring-principal"

// AnnotationDeclaringPrincipal is the annotation key stamped on root declaration
// CRDs at CREATE time. Carries the identity of the requesting principal.
// seam-core-schema.md §7 Declaration 6, guardian-schema.md §17.
const AnnotationDeclaringPrincipal = "infrastructure.ontai.dev/declaring-principal"

// declaringPrincipalKinds is the set of root declaration kinds that receive the
// declaring-principal annotation at CREATE time.
var declaringPrincipalKinds = map[string]bool{
	"TalosCluster":              true,
	"SeamInfrastructureCluster": true,
	"SeamInfrastructureMachine": true,
	"ClusterPack":               true,
	"PackExecution":             true,
	"PackInstance":              true,
	"RBACPolicy":                true,
	"RBACProfile":               true,
	"IdentityBinding":           true,
}

// NewDeclaringPrincipalHandler returns a DeclaringPrincipalHandler bound to
// the given BootstrapWindow.
func NewDeclaringPrincipalHandler(window *BootstrapWindow) *DeclaringPrincipalHandler {
	return &DeclaringPrincipalHandler{bootstrapWindow: window}
}

// DeclaringPrincipalHandler is a controller-runtime admission.Handler that
// stamps the annotation infrastructure.ontai.dev/declaring-principal on root
// declaration CRDs at CREATE time.
//
// The annotation value is the UserInfo.Username from the admission request.
// Only CREATE operations are mutated. UPDATE and DELETE are always admitted
// without modification.
//
// During the bootstrap window (INV-020) the annotation is not stamped.
// The LineageController treats an absent annotation as "system:unknown"
// when populating rootBinding.declaringPrincipal.
//
// seam-core-schema.md §7 Declaration 6.
type DeclaringPrincipalHandler struct {
	bootstrapWindow *BootstrapWindow
}

// Handle implements admission.Handler.
func (h *DeclaringPrincipalHandler) Handle(_ context.Context, req admission.Request) admission.Response {
	if req.Operation != admissionv1.Create {
		return admission.Allowed("")
	}

	if !declaringPrincipalKinds[req.Kind.Kind] {
		return admission.Allowed("")
	}

	// During the bootstrap window the annotation is not stamped. INV-020.
	if h.bootstrapWindow.IsOpen() {
		return admission.Allowed("")
	}

	principal := req.UserInfo.Username
	if principal == "" {
		return admission.Allowed("")
	}

	patch, err := buildAnnotationPatch(req.Object.Raw, AnnotationDeclaringPrincipal, principal)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("build annotation patch: %w", err))
	}

	return admission.Response{
		AdmissionResponse: admissionv1.AdmissionResponse{
			Allowed: true,
			Patch:   patch,
			PatchType: func() *admissionv1.PatchType {
				pt := admissionv1.PatchTypeJSONPatch
				return &pt
			}(),
		},
	}
}

// buildAnnotationPatch constructs a JSON patch that adds or replaces the given
// annotation key on the raw admission object. Returns the serialized JSON patch
// bytes suitable for inclusion in an AdmissionResponse.
func buildAnnotationPatch(raw []byte, key, value string) ([]byte, error) {
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("unmarshal object: %w", err)
	}

	metadata, _ := obj["metadata"].(map[string]interface{})
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	annotations, _ := metadata["annotations"].(map[string]interface{})

	var ops []map[string]interface{}
	if annotations == nil {
		ops = []map[string]interface{}{
			{"op": "add", "path": "/metadata/annotations", "value": map[string]string{key: value}},
		}
	} else {
		ops = []map[string]interface{}{
			{"op": "add", "path": "/metadata/annotations/" + jsonPatchEscapeKey(key), "value": value},
		}
	}

	return json.Marshal(ops)
}

// jsonPatchEscapeKey escapes a JSON Pointer token per RFC 6901:
// ~ -> ~0, / -> ~1. Required for annotation keys containing slashes.
func jsonPatchEscapeKey(key string) string {
	out := make([]byte, 0, len(key)+4)
	for i := 0; i < len(key); i++ {
		switch key[i] {
		case '~':
			out = append(out, '~', '0')
		case '/':
			out = append(out, '~', '1')
		default:
			out = append(out, key[i])
		}
	}
	return string(out)
}
