package controller

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/database"
	seamconditions "github.com/ontai-dev/seam-core/pkg/conditions"
)

// defaultFreshnessWindowSeconds is used when spec.FreshnessWindowSeconds is zero
// (unset or defaulted before the kubebuilder defaulting webhook applies).
const defaultFreshnessWindowSeconds = 300

// PermissionSnapshotReconciler watches PermissionSnapshot CRs and:
//  1. Initialises the LineageSynced condition to False on first observation.
//  2. Evaluates freshness: compares the current time against spec.SnapshotTimestamp
//     relative to spec.FreshnessWindowSeconds and sets the Fresh condition accordingly.
//  3. Requeues after FreshnessWindowSeconds so a snapshot that was fresh on last
//     reconcile is re-evaluated when it may become stale.
//
// This reconciler runs under both role=management and role=tenant — both roles need
// freshness tracking. guardian-schema.md §7, §15.
//
// The reconciler does NOT set the Signed or DriftDetected status fields; those are
// written exclusively by the Conductor signing loop (INV-026) and the Guardian drift
// detection loop respectively.
//
// +kubebuilder:rbac:groups=security.ontai.dev,resources=permissionsnapshots,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=permissionsnapshots/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
type PermissionSnapshotReconciler struct {
	// Client is the controller-runtime client for Kubernetes API access.
	Client client.Client

	// Scheme is the runtime scheme used for object type registration.
	Scheme *runtime.Scheme

	// Recorder is the Kubernetes event recorder for emitting Warning and Normal events.
	Recorder record.EventRecorder

	// Now is the time provider. In production it returns time.Now(). Inject a fixed
	// time in tests to make freshness assertions deterministic.
	Now func() time.Time

	// AuditWriter receives operational audit events from this reconciler.
	// Nil is safe — events are silently dropped when no writer is configured.
	AuditWriter database.AuditWriter
}

// now returns the current time, using the injected provider if set.
func (r *PermissionSnapshotReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Reconcile is the main reconciliation loop for PermissionSnapshot.
func (r *PermissionSnapshotReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Step 1 — Fetch the PermissionSnapshot CR.
	snapshot := &securityv1alpha1.PermissionSnapshot{}
	if err := r.Client.Get(ctx, req.NamespacedName, snapshot); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("PermissionSnapshot not found — likely deleted, ignoring",
				"namespacedName", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get PermissionSnapshot %s: %w", req.NamespacedName, err)
	}

	// Step 2 — Defer status patch.
	patchBase := client.MergeFrom(snapshot.DeepCopy())
	defer func() {
		if err := r.Client.Status().Patch(ctx, snapshot, patchBase); err != nil {
			if !apierrors.IsNotFound(err) {
				logger.Error(err, "failed to patch PermissionSnapshot status",
					"name", snapshot.Name, "namespace", snapshot.Namespace)
			}
		}
	}()

	// Step 3 — Advance ObservedGeneration.
	snapshot.Status.ObservedGeneration = snapshot.Generation

	// Step 4 — Initialize LineageSynced on first observation.
	// One-time write only. InfrastructureLineageController takes ownership when deployed.
	// seam-core-schema.md §7 Declaration 5.
	if securityv1alpha1.FindCondition(snapshot.Status.Conditions, securityv1alpha1.ConditionTypeLineageSynced) == nil {
		securityv1alpha1.SetCondition(
			&snapshot.Status.Conditions,
			securityv1alpha1.ConditionTypeLineageSynced,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonLineageControllerAbsent,
			"InfrastructureLineageController is not yet deployed.",
			snapshot.Generation,
		)
	}

	// Step 5 — Evaluate FreshnessCondition.
	// Use SnapshotTimestamp if set; fall back to GeneratedAt (EPGReconciler compat).
	var snapshotTime *metav1.Time
	if snapshot.Spec.SnapshotTimestamp != nil {
		snapshotTime = snapshot.Spec.SnapshotTimestamp
	} else if !snapshot.Spec.GeneratedAt.IsZero() {
		snapshotTime = &snapshot.Spec.GeneratedAt
	}

	window := snapshot.Spec.FreshnessWindowSeconds
	if window <= 0 {
		window = defaultFreshnessWindowSeconds
	}

	if snapshotTime == nil || snapshotTime.IsZero() {
		// No timestamp available — cannot evaluate freshness. Leave condition absent
		// and requeue after the window so we re-check once a timestamp is set.
		logger.Info("PermissionSnapshot has no SnapshotTimestamp or GeneratedAt — skipping freshness evaluation",
			"name", snapshot.Name, "namespace", snapshot.Namespace)
		return ctrl.Result{RequeueAfter: time.Duration(window) * time.Second}, nil
	}

	age := r.now().Sub(snapshotTime.Time)
	windowDuration := time.Duration(window) * time.Second
	isFresh := age <= windowDuration

	if isFresh {
		securityv1alpha1.SetCondition(
			&snapshot.Status.Conditions,
			seamconditions.ConditionTypePermissionSnapshotFresh,
			metav1.ConditionTrue,
			seamconditions.ReasonSnapshotFresh,
			fmt.Sprintf("Snapshot age %s is within freshness window %s.", age.Round(time.Second), windowDuration),
			snapshot.Generation,
		)
		logger.Info("PermissionSnapshot is fresh",
			"name", snapshot.Name, "namespace", snapshot.Namespace,
			"age", age, "window", windowDuration)
	} else {
		securityv1alpha1.SetCondition(
			&snapshot.Status.Conditions,
			seamconditions.ConditionTypePermissionSnapshotFresh,
			metav1.ConditionFalse,
			seamconditions.ReasonSnapshotStale,
			fmt.Sprintf("Snapshot age %s exceeds freshness window %s.", age.Round(time.Second), windowDuration),
			snapshot.Generation,
		)
		r.Recorder.Event(snapshot, "Warning", "SnapshotStale",
			fmt.Sprintf("PermissionSnapshot age %s exceeds freshness window %s — target cluster may be serving stale permissions.",
				age.Round(time.Second), windowDuration))
		logger.Info("PermissionSnapshot is stale",
			"name", snapshot.Name, "namespace", snapshot.Namespace,
			"age", age, "window", windowDuration)
	}

	// Step 6 — Emit a drift audit event if the snapshot is currently drifted.
	// The EPGReconciler drift loop emits on transitions; this provides a periodic
	// audit trail for snapshots that remain drifted across multiple requeue cycles.
	if snapshot.Status.Drift {
		writeAudit(ctx, r.AuditWriter, database.AuditEvent{
			ClusterID:      "management",
			Subject:        "guardian",
			Action:         "permissionsnapshot.drift_detected",
			Resource:       snapshot.Name,
			Decision:       "system",
			MatchedPolicy:  "DriftObserved",
			SequenceNumber: auditSeq(),
		})
	}

	// Step 7 — Fresh snapshots requeue after the window so they are re-evaluated
	// when they may become stale. Stale snapshots return without requeue — the
	// EPGReconciler watches for the Fresh=False status transition and enqueues
	// a full EPG recompute immediately.
	if isFresh {
		return ctrl.Result{RequeueAfter: windowDuration}, nil
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers PermissionSnapshotReconciler as the controller for PermissionSnapshot.
func (r *PermissionSnapshotReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.PermissionSnapshot{}).
		Complete(r)
}
