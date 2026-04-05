package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
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
//
// Full implementation is in WS3 of session/41.
type AuditSinkReconciler struct {
	// Client is the controller-runtime client for Kubernetes API access.
	Client client.Client

	// Scheme is the runtime scheme used for object type registration.
	Scheme *runtime.Scheme

	// Recorder is the Kubernetes event recorder.
	Recorder record.EventRecorder

	// DB is the database.AuditDatabase interface used for deduplication and event
	// insertion. Injected at construction time; must be non-nil when role=management.
	// The interface is defined in internal/database so that mock implementations
	// can be injected in tests without importing a real CNPG driver.
	DB database.AuditDatabase
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

	logger.Info("AuditSinkReconciler: stub — full implementation in WS3",
		"name", cm.Name, "namespace", cm.Namespace, "clusterID", clusterID)
	return ctrl.Result{}, nil
}

// SetupWithManager registers AuditSinkReconciler to watch audit batch ConfigMaps.
func (r *AuditSinkReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}).
		Complete(r)
}
