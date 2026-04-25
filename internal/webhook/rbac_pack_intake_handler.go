// Package webhook -- RBAC pack intake handler for ClusterPack RBAC layer delivery.
// Accepts YAML manifests from the pack-deploy capability and wraps them with the
// guardian ownership annotation before applying via SSA. guardian-schema.md §6,
// wrapper-schema.md §4, INV-004.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	sigsyaml "sigs.k8s.io/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/ontai-dev/guardian/internal/database"
)

// rbacPolicyGVK is the GroupVersionKind used to look up RBACPolicy objects via
// the dynamic client when checking for cluster-policy existence. guardian-schema.md §6.
var rbacPolicyGVK = schema.GroupVersionKind{
	Group:   "security.ontai.dev",
	Version: "v1alpha1",
	Kind:    "RBACPolicy",
}

// RBACPackIntakeWebhookPath is the HTTP path for the ClusterPack RBAC intake endpoint.
// The pack-deploy capability POSTs the RBAC layer manifests here before applying
// the workload layer. wrapper-schema.md §4.
const RBACPackIntakeWebhookPath = "/rbac-intake/pack"

// PackIntakeRequest is the JSON body accepted by the /rbac-intake/pack endpoint.
// ComponentName names the ClusterPack component (e.g., "nginx-ingress").
// Manifests is a slice of raw YAML manifest strings from the RBAC OCI layer.
// TargetCluster identifies the cluster the pack is being deployed to; used for
// RBACProfile namespace routing (seam-tenant-{targetCluster}) and audit.
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

// EnsurePackRBACProfileCRs creates or updates the RBACProfile for a component in
// seam-tenant-{targetCluster}. No per-component RBACPolicy or PermissionSet is
// created -- cluster-policy (Layer 2) is the single governing policy for all
// components. Component permissions are declared inline in permissionDeclarations.
// guardian-schema.md §6, §19 Layer 3. CS-INV-005, CS-INV-008.
//
// Guard: returns an error if cluster-policy does not yet exist in the target
// namespace. ClusterRBACPolicyReconciler (§18) must provision it first.
func EnsurePackRBACProfileCRs(ctx context.Context, c client.Client, componentName, targetCluster string) error {
	ns := "seam-tenant-" + targetCluster

	// Guard: cluster-policy must exist before any component RBACProfile can reference it.
	// guardian-schema.md §19 Layer 2, §6 intake guard.
	clusterPolicy := &unstructured.Unstructured{}
	clusterPolicy.SetGroupVersionKind(rbacPolicyGVK)
	if err := c.Get(ctx, client.ObjectKey{Name: "cluster-policy", Namespace: ns}, clusterPolicy); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("cluster-policy not yet provisioned in %s: ClusterRBACPolicyReconciler must run first", ns)
		}
		return fmt.Errorf("get cluster-policy in %s: %w", ns, err)
	}

	// RBACProfile -- one per component, references cluster-policy (Layer 2).
	// No separate PermissionSet object; permission claims declared inline.
	// guardian-schema.md §19 Layer 3, CS-INV-008.
	profile := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "security.ontai.dev/v1alpha1",
			"kind":       "RBACProfile",
			"metadata": map[string]interface{}{
				"name":      componentName,
				"namespace": ns,
				"annotations": map[string]interface{}{
					rbacOwnerAnnotation: rbacOwnerGuardian,
				},
				"labels": map[string]interface{}{
					"ontai.dev/managed-by":  "guardian",
					"ontai.dev/policy-type": "component",
				},
			},
			"spec": map[string]interface{}{
				"principalRef":   componentName,
				"targetClusters": []interface{}{targetCluster},
				"rbacPolicyRef":  "cluster-policy",
				// Declares permissions inline via the shared cluster ceiling (§19 Layer 3).
				// No per-component PermissionSet exists; cluster-maximum is the sole ceiling.
				"permissionDeclarations": []interface{}{
					map[string]interface{}{
						"permissionSetRef": "cluster-maximum",
						"scope":            "cluster",
					},
				},
			},
		},
	}
	profileConfig := client.ApplyConfigurationFromUnstructured(profile)
	if err := c.Apply(ctx, profileConfig, client.ForceOwnership, client.FieldOwner(intakeSSAFieldManager)); err != nil {
		return fmt.Errorf("apply RBACProfile %s/%s: %w", ns, componentName, err)
	}

	return nil
}

// ensureRBACProfileCRs delegates to EnsurePackRBACProfileCRs using the handler's client.
func (h *RBACPackIntakeHandler) ensureRBACProfileCRs(ctx context.Context, componentName, targetCluster string) error {
	return EnsurePackRBACProfileCRs(ctx, h.client, componentName, targetCluster)
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

	// After applying all RBAC manifests, synthesise the guardian security CRs
	// required for RBACProfileReconciler to set provisioned=true.
	// The conductor wait-rbac-profile step polls this profile.
	// CS-INV-005: RBACProfileReconciler sets provisioned=true; we only CREATE the CR.
	if err := h.ensureRBACProfileCRs(ctx, req.ComponentName, req.TargetCluster); err != nil {
		logger.Error(err, "rbac-intake/pack: failed to ensure RBACProfile CRs",
			"component", req.ComponentName, "targetCluster", req.TargetCluster)
		http.Error(w, fmt.Sprintf("ensure RBACProfile CRs: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(PackIntakeResponse{
		ComponentName: req.ComponentName,
		TargetCluster: req.TargetCluster,
		Wrapped:       wrapped,
	})
}
