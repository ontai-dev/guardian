// Package webhook -- RBAC pack intake handler for ClusterPack RBAC layer delivery.
// Accepts YAML manifests from the pack-deploy capability and wraps them with the
// guardian ownership annotation before applying via SSA. guardian-schema.md §6,
// wrapper-schema.md §4, INV-004.
package webhook

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	sigsyaml "sigs.k8s.io/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/ontai-dev/guardian/internal/database"
)

// RBACPackIntakeWebhookPath is the HTTP path for the ClusterPack RBAC intake endpoint.
// The pack-deploy capability POSTs the RBAC layer manifests here before applying
// the workload layer. wrapper-schema.md §4.
const RBACPackIntakeWebhookPath = "/rbac-intake/pack"

// PackIntakeRequest is the JSON body accepted by the /rbac-intake/pack endpoint.
// ComponentName names the ClusterPack component (e.g., "nginx-ingress").
// Manifests is a slice of raw YAML manifest strings from the RBAC OCI layer.
// TargetCluster identifies the cluster the pack is being deployed to; used for
// RBACProfile namespace routing (tenant-{targetCluster}) and audit.
type PackIntakeRequest struct {
	ComponentName string   `json:"componentName"`
	Manifests     []string `json:"manifests"`
	TargetCluster string   `json:"targetCluster"`
}

// PackIntakeResponse is the JSON body returned by /rbac-intake/pack on success.
type PackIntakeResponse struct {
	ComponentName string `json:"componentName"`
	TargetCluster string `json:"targetCluster"`
	Wrapped       int    `json:"wrapped"`
}

// RBACPackIntakeHandler handles POST /rbac-intake/pack requests from pack-deploy.
// It accepts YAML manifests from the RBAC layer of a ClusterPack OCI artifact,
// stamps ontai.dev/rbac-owner=guardian on each, and applies via SSA.
// INV-004: guardian owns all RBAC on every cluster; pack-deploy never writes
// RBAC resources directly. guardian-schema.md §6, wrapper-schema.md §4.
type RBACPackIntakeHandler struct {
	client      client.Client
	auditWriter database.AuditWriter
}

// NewRBACPackIntakeHandler creates a new RBACPackIntakeHandler.
func NewRBACPackIntakeHandler(c client.Client, aw database.AuditWriter) *RBACPackIntakeHandler {
	return &RBACPackIntakeHandler{client: c, auditWriter: aw}
}

// ServeHTTP implements http.Handler for the /rbac-intake/pack endpoint.
func (h *RBACPackIntakeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req PackIntakeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
		return
	}

	if req.ComponentName == "" {
		http.Error(w, "bad request: componentName is required", http.StatusBadRequest)
		return
	}
	if req.TargetCluster == "" {
		http.Error(w, "bad request: targetCluster is required", http.StatusBadRequest)
		return
	}

	wrapped := 0
	for i, yamlDoc := range req.Manifests {
		if strings.TrimSpace(yamlDoc) == "" {
			continue
		}

		jsonBytes, err := sigsyaml.YAMLToJSON([]byte(yamlDoc))
		if err != nil {
			logger.Error(err, "rbac-intake/pack: failed to convert manifest YAML to JSON",
				"component", req.ComponentName, "index", i)
			http.Error(w, fmt.Sprintf("manifest[%d]: yaml to json: %v", i, err), http.StatusBadRequest)
			return
		}

		obj := &unstructured.Unstructured{}
		if err := obj.UnmarshalJSON(jsonBytes); err != nil {
			logger.Error(err, "rbac-intake/pack: failed to unmarshal manifest",
				"component", req.ComponentName, "index", i)
			http.Error(w, fmt.Sprintf("manifest[%d]: unmarshal: %v", i, err), http.StatusBadRequest)
			return
		}

		annotations := obj.GetAnnotations()
		if annotations == nil {
			annotations = make(map[string]string)
		}
		annotations[rbacOwnerAnnotation] = rbacOwnerGuardian
		obj.SetAnnotations(annotations)

		applyConfig := client.ApplyConfigurationFromUnstructured(obj)
		if err := h.client.Apply(ctx, applyConfig,
			client.ForceOwnership,
			client.FieldOwner(intakeSSAFieldManager)); err != nil {
			logger.Error(err, "rbac-intake/pack: failed to apply resource",
				"component", req.ComponentName,
				"targetCluster", req.TargetCluster,
				"kind", obj.GetKind(),
				"name", obj.GetName())
			http.Error(w, fmt.Sprintf("apply %s/%s: %v",
				obj.GetKind(), obj.GetName(), err), http.StatusInternalServerError)
			return
		}

		wrapped++
		webhookAuditWrite(ctx, h.auditWriter, database.AuditEvent{
			ClusterID:      req.TargetCluster,
			Subject:        "guardian-pack-intake",
			Action:         "rbac.wrapped",
			Resource:       obj.GetName(),
			Decision:       "admit",
			MatchedPolicy:  fmt.Sprintf("component=%s,targetCluster=%s", req.ComponentName, req.TargetCluster),
			SequenceNumber: time.Now().UnixNano(),
		})
		logger.Info("rbac-intake/pack: wrapped resource",
			"component", req.ComponentName,
			"targetCluster", req.TargetCluster,
			"kind", obj.GetKind(),
			"name", obj.GetName())
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(PackIntakeResponse{
		ComponentName: req.ComponentName,
		TargetCluster: req.TargetCluster,
		Wrapped:       wrapped,
	})
}
