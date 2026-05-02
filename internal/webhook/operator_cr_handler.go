package webhook

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/ontai-dev/guardian/internal/database"
)

// OperatorCRGuardHandler is a controller-runtime admission.Handler that prevents
// any non-operator principal from updating operator-created CRs.
//
// It intercepts UPDATE requests for PackInstance, RunnerConfig, PermissionSnapshot,
// and PackExecution. Requests from principals other than seam operator service
// accounts (system:serviceaccount:{OperatorNamespace}:*) are rejected at admission.
// G-BL-CR-IMMUTABILITY.
type OperatorCRGuardHandler struct {
	bootstrapWindow   *BootstrapWindow
	auditWriter       database.AuditWriter
	operatorNamespace string
}

// Handle implements admission.Handler.
// It extracts the requesting principal and kind from the admission request,
// delegates to EvaluateOperatorAuthorship, and returns the appropriate response.
func (h *OperatorCRGuardHandler) Handle(ctx context.Context, req admission.Request) admission.Response {
	if req.Object.Raw == nil {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("empty object in admission request"))
	}

	decision := EvaluateOperatorAuthorship(OperatorCRGuardRequest{
		Kind:                req.Kind.Kind,
		Operation:           AdmissionOperation(req.Operation),
		Username:            req.UserInfo.Username,
		BootstrapWindowOpen: h.bootstrapWindow.IsOpen(),
		OperatorNamespace:   h.operatorNamespace,
	})

	if !decision.Allowed {
		log.FromContext(ctx).Info("operator-cr authorship violation",
			"kind", req.Kind.Kind,
			"name", req.Name,
			"namespace", req.Namespace,
			"principal", req.UserInfo.Username,
		)
		webhookAuditWrite(ctx, h.auditWriter, database.AuditEvent{
			ClusterID:      "management",
			Subject:        req.UserInfo.Username,
			Action:         "operator-cr.denied",
			Resource:       req.Name,
			Decision:       "deny",
			MatchedPolicy:  decision.Reason,
			SequenceNumber: time.Now().UnixNano(),
		})
		return admission.Denied(decision.Reason)
	}

	return admission.Allowed("")
}
