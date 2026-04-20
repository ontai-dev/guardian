package webhook

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/ontai-dev/guardian/internal/database"
)

// RBACIntakeWebhookPath is the HTTP path where the RBAC intake handler is registered.
// The Compiler enable phase POST-s RBAC resources extracted from third-party Helm chart
// output to this endpoint. Guardian wraps each resource with the guardian ownership
// annotation and applies it via SSA. guardian-schema.md §6, CS-INV-007.
const RBACIntakeWebhookPath = "/rbac-intake"

// rbacOwnerAnnotation is the ownership annotation that Guardian stamps on every
// RBAC resource it wraps. The admission webhook enforces this annotation at admission
// time on the management cluster and any target cluster hosting Guardian.
const rbacOwnerAnnotation = "ontai.dev/rbac-owner"

// rbacOwnerGuardian is the value stamped into rbacOwnerAnnotation when Guardian
// wraps a third-party RBAC resource. guardian-schema.md §6.
const rbacOwnerGuardian = "guardian"

// intakeSSAFieldManager is the field manager name used for SSA applies of wrapped
// RBAC resources. Consistent field manager ensures idempotent re-applies on
// Helm upgrade without ownership conflicts.
const intakeSSAFieldManager = "guardian-rbac-intake"

// IntakeRequest is the JSON body accepted by the /rbac-intake endpoint.
// Component names the third-party component whose RBAC is being wrapped (e.g. "cilium").
// Resources is a slice of raw RBAC resource JSON objects in any RBAC API group.
type IntakeRequest struct {
	Component string            `json:"component"`
	Resources []json.RawMessage `json:"resources"`
}

// IntakeResponse is the JSON body returned by the /rbac-intake endpoint on success.
type IntakeResponse struct {
	Component string `json:"component"`
	Wrapped   int    `json:"wrapped"`
}

// RBACIntakeHandler handles POST /rbac-intake requests from the Compiler enable phase.
// It stamps ontai.dev/rbac-owner=guardian on each submitted resource and applies it
// via SSA, making Guardian the authoritative RBAC owner for the component.
//
// CS-INV-007: wrapping, not replacement. SSA apply is safe across Helm upgrades
// because only the ownership annotation field is managed by the intake field manager.
// Drift from the declared state raises a policy violation (observed by the admission
// webhook); resources are never silently overwritten.
//
// The Kubernetes client must have RBAC write permissions for ClusterRole,
// ClusterRoleBinding, Role, and RoleBinding. guardian-schema.md §6.
type RBACIntakeHandler struct {
	client      client.Client
	auditWriter database.AuditWriter
}

// NewRBACIntakeHandler creates a new RBACIntakeHandler.
func NewRBACIntakeHandler(c client.Client, aw database.AuditWriter) *RBACIntakeHandler {
	return &RBACIntakeHandler{client: c, auditWriter: aw}
}

// ServeHTTP implements http.Handler for the /rbac-intake endpoint.
func (h *RBACIntakeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req IntakeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
		return
	}

	wrapped := 0
	for _, raw := range req.Resources {
		obj := &unstructured.Unstructured{}
		if err := obj.UnmarshalJSON(raw); err != nil {
			logger.Error(err, "rbac-intake: failed to unmarshal resource",
				"component", req.Component)
			http.Error(w, fmt.Sprintf("unmarshal resource: %v", err), http.StatusBadRequest)
			return
		}

		// Stamp the guardian ownership annotation. CS-INV-007.
		annotations := obj.GetAnnotations()
		if annotations == nil {
			annotations = make(map[string]string)
		}
		annotations[rbacOwnerAnnotation] = rbacOwnerGuardian
		obj.SetAnnotations(annotations)

		// Apply via SSA so that idempotent re-applies on Helm upgrade are safe.
		// Only the ownership annotation field is owned by this field manager.
		applyConfig := client.ApplyConfigurationFromUnstructured(obj)
		if err := h.client.Apply(ctx, applyConfig,
			client.ForceOwnership,
			client.FieldOwner(intakeSSAFieldManager)); err != nil {
			logger.Error(err, "rbac-intake: failed to apply resource",
				"component", req.Component,
				"kind", obj.GetKind(),
				"name", obj.GetName())
			http.Error(w, fmt.Sprintf("apply resource %s/%s: %v",
				obj.GetKind(), obj.GetName(), err), http.StatusInternalServerError)
			return
		}

		wrapped++
		webhookAuditWrite(ctx, h.auditWriter, database.AuditEvent{
			ClusterID:      "management",
			Subject:        "guardian-intake",
			Action:         "rbac.wrapped",
			Resource:       obj.GetName(),
			Decision:       "admit",
			MatchedPolicy:  fmt.Sprintf("component=%s", req.Component),
			SequenceNumber: time.Now().UnixNano(),
		})
		logger.Info("rbac-intake: wrapped resource",
			"component", req.Component,
			"kind", obj.GetKind(),
			"name", obj.GetName())
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(IntakeResponse{
		Component: req.Component,
		Wrapped:   wrapped,
	})
}

