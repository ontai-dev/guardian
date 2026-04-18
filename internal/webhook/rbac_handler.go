package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/ontai-dev/guardian/internal/database"
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
	// namespaceMode resolves the per-namespace enforcement tier before calling
	// EvaluateAdmission. Exempt namespaces bypass all policy evaluation.
	// Observe namespaces run full evaluation but always return allowed.
	// INV-020, CS-INV-004.
	namespaceMode NamespaceModeResolver
	// auditWriter receives admission audit events. Nil is safe.
	auditWriter database.AuditWriter
}

// partialObject is used for partial JSON unmarshalling of the admitted resource.
// Only the metadata.annotations field is needed for the admission decision.
type partialObject struct {
	Metadata struct {
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
}

// Handle implements admission.Handler.
// It resolves the per-namespace enforcement tier, extracts the resource kind
// and annotations from the admission request, reads the current bootstrap window
// state, delegates to EvaluateAdmission, and returns the appropriate response.
// When EvaluateAdmission returns ObservedDeny=true (observe mode would-deny),
// the handler logs the observation but still returns allowed.
func (h *RBACAdmissionHandler) Handle(ctx context.Context, req admission.Request) admission.Response {
	var obj partialObject
	if err := json.Unmarshal(req.Object.Raw, &obj); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	nsMode := h.namespaceMode.ResolveMode(ctx, req.Namespace)

	decision := EvaluateAdmission(AdmissionRequest{
		Kind:                req.Kind.Kind,
		Operation:           AdmissionOperation(req.Operation),
		Annotations:         obj.Metadata.Annotations,
		BootstrapWindowOpen: h.bootstrapWindow.IsOpen(),
		NSMode:              nsMode,
	})

	if decision.ObservedDeny {
		log.FromContext(ctx).Info("would-deny observation",
			"namespace", req.Namespace,
			"kind", req.Kind.Kind,
			"operation", req.Operation,
			"reason", decision.Reason,
		)
		webhookAuditWrite(ctx, h.auditWriter, database.AuditEvent{
			ClusterID:      "management",
			Subject:        req.UserInfo.Username,
			Action:         "rbac.would_deny",
			Resource:       req.Name,
			Decision:       "audit",
			MatchedPolicy:  decision.Reason,
			SequenceNumber: time.Now().UnixNano(),
		})
	}

	if decision.Allowed {
		// Emit an audit event for admits of RBAC resources only — admitting
		// non-RBAC resources is not audit-significant for the guardian log.
		if InterceptedKinds[req.Kind.Kind] {
			webhookAuditWrite(ctx, h.auditWriter, database.AuditEvent{
				ClusterID:      "management",
				Subject:        req.UserInfo.Username,
				Action:         "rbac.admitted",
				Resource:       req.Name,
				Decision:       "admit",
				MatchedPolicy:  "",
				SequenceNumber: time.Now().UnixNano(),
			})
		}
		return admission.Allowed("")
	}

	webhookAuditWrite(ctx, h.auditWriter, database.AuditEvent{
		ClusterID:      "management",
		Subject:        req.UserInfo.Username,
		Action:         "rbac.denied",
		Resource:       req.Name,
		Decision:       "deny",
		MatchedPolicy:  decision.Reason,
		SequenceNumber: time.Now().UnixNano(),
	})
	return admission.Denied(decision.Reason)
}

// webhookAuditWrite is a nil-safe helper for audit writes from the webhook package.
// Failures are discarded — admission decisions must never be blocked by audit errors.
func webhookAuditWrite(ctx context.Context, aw database.AuditWriter, event database.AuditEvent) {
	if aw == nil {
		return
	}
	_ = aw.Write(ctx, event)
}

// InjectDecoder injects the decoder from controller-runtime's webhook builder.
// The decoder is stored but not used for admission decisions — annotations are
// extracted from raw JSON to avoid a dependency on decoded object types.
func (h *RBACAdmissionHandler) InjectDecoder(d *admission.Decoder) error {
	h.decoder = d
	return nil
}
