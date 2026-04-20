package controller

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientevents "k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/ontai-dev/guardian/internal/database"
)

// AuditSinkLabelKey is the label selector used to identify ConfigMaps that
// carry AuditEventBatch payloads staged by tenant Conductors.
// conductor-schema.md §18, guardian-schema.md §15.
const AuditSinkLabelKey = "seam.ontai.dev/audit-batch"

// AuditSinkLabelValue is the value that must be present on the audit-batch label.
const AuditSinkLabelValue = "true"

// auditBatchDataKey is the ConfigMap data key that holds the JSON-encoded event batch.
const auditBatchDataKey = "events"

// auditBatchEvent is the wire format for a single event in an AuditEventBatch ConfigMap.
// It matches the fields written by AuditForwarderController.
type auditBatchEvent struct {
	SequenceNumber int64  `json:"sequenceNumber"`
	Subject        string `json:"subject"`
	Action         string `json:"action"`
	Resource       string `json:"resource"`
	Decision       string `json:"decision"`
	MatchedPolicy  string `json:"matchedPolicy"`
}

// AuditSinkReconciler watches for AuditEventBatch ConfigMaps delivered by tenant
// Conductors via the federation channel staging area. It deduplicates events on
// sequence number, inserts non-duplicate events into the audit_events table, and
// deletes the ConfigMap after processing.
//
// Role: management only. guardian-schema.md §15.
//
// The reconciler processes ConfigMaps in seam-system labelled with
// seam.ontai.dev/audit-batch=true. The real federation channel delivery is wired
// in the Conductor federation session (conductor-schema.md §18).
type AuditSinkReconciler struct {
	// Client is the controller-runtime client for Kubernetes API access.
	Client client.Client

	// Scheme is the runtime scheme used for object type registration.
	Scheme *runtime.Scheme

	// Recorder is the Kubernetes event recorder.
	Recorder clientevents.EventRecorder

	// DB is the database.AuditDatabase interface used for deduplication and event
	// insertion. Injected at construction time; must be non-nil when role=management.
	// The interface is defined in internal/database so that mock implementations
	// can be injected in tests without importing a real CNPG driver.
	DB database.AuditDatabase

	// AuditWriter receives management-cluster audit events (distinct from tenant
	// events forwarded via DB). Nil is safe — events are silently dropped when no
	// writer is configured.
	AuditWriter database.AuditWriter
}

// Reconcile processes an audit batch ConfigMap.
//
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
func (r *AuditSinkReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	cm := &corev1.ConfigMap{}
	if err := r.Client.Get(ctx, req.NamespacedName, cm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Only process ConfigMaps with the audit-batch label.
	if cm.Labels[AuditSinkLabelKey] != AuditSinkLabelValue {
		return ctrl.Result{}, nil
	}

	clusterID := cm.Annotations["seam.ontai.dev/cluster-id"]
	if clusterID == "" {
		logger.Info("audit batch ConfigMap missing cluster-id annotation, skipping",
			"name", cm.Name, "namespace", cm.Namespace)
		return ctrl.Result{}, nil
	}

	// Parse the event batch from the ConfigMap data.
	raw, ok := cm.Data[auditBatchDataKey]
	if !ok {
		logger.Info("audit batch ConfigMap has no 'events' key, deleting",
			"name", cm.Name, "namespace", cm.Namespace)
		return ctrl.Result{}, r.deleteConfigMap(ctx, cm)
	}

	var events []auditBatchEvent
	if err := json.Unmarshal([]byte(raw), &events); err != nil {
		logger.Error(err, "failed to parse audit batch events, deleting malformed ConfigMap",
			"name", cm.Name, "namespace", cm.Namespace)
		return ctrl.Result{}, r.deleteConfigMap(ctx, cm)
	}

	inserted, skipped, err := r.processBatch(ctx, clusterID, events)
	if err != nil {
		// Return error to trigger requeue — do not delete the ConfigMap yet.
		return ctrl.Result{}, fmt.Errorf("process audit batch %s/%s: %w", cm.Namespace, cm.Name, err)
	}

	logger.Info("audit batch processed",
		"name", cm.Name, "namespace", cm.Namespace,
		"clusterID", clusterID,
		"inserted", inserted, "skipped", skipped)

	writeAudit(ctx, r.AuditWriter, database.AuditEvent{
		ClusterID:      "management",
		Subject:        "guardian",
		Action:         "audit_batch.processed",
		Resource:       cm.Name,
		Decision:       "system",
		MatchedPolicy:  clusterID,
		SequenceNumber: int64(inserted), //nolint:gosec — inserted is a non-negative count
	})

	// Delete the ConfigMap after successful processing.
	return ctrl.Result{}, r.deleteConfigMap(ctx, cm)
}

// processBatch deduplicates and inserts events. Returns counts of inserted and skipped.
func (r *AuditSinkReconciler) processBatch(ctx context.Context, clusterID string, events []auditBatchEvent) (inserted, skipped int, err error) {
	for _, e := range events {
		exists, checkErr := r.DB.EventExists(ctx, clusterID, e.SequenceNumber)
		if checkErr != nil {
			return inserted, skipped, fmt.Errorf("EventExists(clusterID=%s seq=%d): %w",
				clusterID, e.SequenceNumber, checkErr)
		}
		if exists {
			skipped++
			continue
		}
		if insertErr := r.DB.InsertEvent(ctx, database.AuditEvent{
			ClusterID:      clusterID,
			SequenceNumber: e.SequenceNumber,
			Subject:        e.Subject,
			Action:         e.Action,
			Resource:       e.Resource,
			Decision:       e.Decision,
			MatchedPolicy:  e.MatchedPolicy,
		}); insertErr != nil {
			return inserted, skipped, fmt.Errorf("InsertEvent(clusterID=%s seq=%d): %w",
				clusterID, e.SequenceNumber, insertErr)
		}
		inserted++
	}
	return inserted, skipped, nil
}

// deleteConfigMap deletes the ConfigMap; IgnoreNotFound so a concurrent delete is fine.
func (r *AuditSinkReconciler) deleteConfigMap(ctx context.Context, cm *corev1.ConfigMap) error {
	if err := r.Client.Delete(ctx, cm); client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("delete ConfigMap %s/%s: %w", cm.Namespace, cm.Name, err)
	}
	return nil
}

// SetupWithManager registers AuditSinkReconciler to watch audit batch ConfigMaps.
func (r *AuditSinkReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}).
		Complete(r)
}
