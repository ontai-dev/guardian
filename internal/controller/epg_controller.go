package controller

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/epg"
)

const (
	// epgSnapshotNamespace is the namespace where PermissionSnapshot CRs are written.
	epgSnapshotNamespace = "security-system"

	// epgFieldOwner is the server-side apply field manager name for EPGReconciler.
	epgFieldOwner = "guardian-epg"

	// epgTriggerName is the fixed reconcile request name used for all EPG recompute triggers.
	// All four annotation-based watch sources map to this key to collapse multiple
	// simultaneous triggers into one computation run.
	epgTriggerName = "epg-trigger"

	// epgDriftTriggerName is the fixed reconcile request name used for drift-check triggers.
	// PermissionSnapshotReceipt and PermissionSnapshot watches map to this key.
	// When dispatched, only reconcileDrift runs — no full EPG recomputation.
	epgDriftTriggerName = "drift-check"
)

// EPGReconciler watches RBACProfile, RBACPolicy, IdentityBinding, and PermissionSet.
// It is triggered when the ontai.dev/epg-recompute-requested=true annotation is present
// on any of these objects.
//
// On trigger, it performs a full EPG recomputation regardless of which object triggered,
// using a fixed reconcile request key (security-system/epg-trigger). This collapses
// multiple simultaneous triggers into one computation run.
//
// Implementation: guardian-design.md §2.
//
// +kubebuilder:rbac:groups=security.ontai.dev,resources=rbacprofiles,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=rbacpolicies,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=identitybindings,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=permissionsets,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=permissionsnapshots,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.ontai.dev,resources=permissionsnapshots/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=permissionsnapshotreceipts,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
type EPGReconciler struct {
	// Client is the controller-runtime client for Kubernetes API access.
	Client client.Client

	// Scheme is the runtime scheme used for object type registration.
	Scheme *runtime.Scheme

	// Recorder is the Kubernetes event recorder for emitting events.
	Recorder record.EventRecorder
}

// Reconcile is the main reconciliation loop for the EPGReconciler.
//
// Two fixed request keys are used:
//   - "epg-trigger": full EPG recomputation path (Sessions 5+).
//   - "drift-check": drift reconciliation only — no EPG recomputation.
//
// Any other request name is logged and ignored (graceful unknown key handling).
func (r *EPGReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Step A — Dispatch based on the fixed request key.
	switch req.Name {
	case epgDriftTriggerName:
		// drift-check path: reconcile drift status on existing snapshots only.
		// Does not recompute the EPG. Does not clear epg-recompute-requested annotations.
		if err := r.reconcileDrift(ctx); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	case epgTriggerName:
		// epg-trigger path: full EPG recomputation. Continue to Step B below.
	default:
		logger.Info("EPGReconciler: unexpected reconcile request key — ignoring", "name", req.Name)
		return ctrl.Result{}, nil
	}

	// Step B — List all RBACProfiles across all namespaces. Filter to provisioned.
	var profileList securityv1alpha1.RBACProfileList
	if err := r.Client.List(ctx, &profileList); err != nil {
		return ctrl.Result{}, fmt.Errorf("EPGReconciler: failed to list RBACProfiles: %w", err)
	}
	var provisioned []securityv1alpha1.RBACProfile
	for _, p := range profileList.Items {
		if p.Status.Provisioned {
			provisioned = append(provisioned, p)
		}
	}
	if len(provisioned) == 0 {
		logger.Info("EPGReconciler: no provisioned profiles — writing empty snapshots")
	}

	// Step C — Clear the epg-recompute-requested annotation from ALL objects that
	// carry it, BEFORE computation begins. This ensures any changes arriving during
	// computation will re-trigger a subsequent run rather than being silently lost.
	r.clearAnnotations(ctx)

	// Step D — Fetch the governing RBACPolicy for each provisioned profile.
	// Map: policy name → RBACPolicy.
	policyMap := make(map[string]securityv1alpha1.RBACPolicy)
	for _, profile := range provisioned {
		policyKey := client.ObjectKey{Namespace: profile.Namespace, Name: profile.Spec.RBACPolicyRef}
		var policy securityv1alpha1.RBACPolicy
		if err := r.Client.Get(ctx, policyKey, &policy); err != nil {
			if apierrors.IsNotFound(err) {
				// Re-annotate the profile to ensure a retry after policy is created.
				r.signalRecompute(ctx, &profile)
				r.Recorder.Eventf(&profile, corev1.EventTypeWarning, "PolicyNotFound",
					"EPGReconciler: RBACPolicy %q not found; requeue in 15s", profile.Spec.RBACPolicyRef)
				logger.Info("EPGReconciler: RBACPolicy not found — requeuing",
					"profile", profile.Name, "policy", profile.Spec.RBACPolicyRef)
				return ctrl.Result{RequeueAfter: 15e9}, nil
			}
			return ctrl.Result{}, fmt.Errorf("EPGReconciler: failed to get RBACPolicy %s: %w",
				policyKey, err)
		}
		policyMap[policy.Name] = policy
	}

	// Step E — Collect all unique PermissionSet names and fetch them.
	// Includes both declaration-side permsets and ceiling permsets from policies.
	type nsName struct{ ns, name string }
	permSetKeys := make(map[nsName]struct{})
	for _, profile := range provisioned {
		for _, decl := range profile.Spec.PermissionDeclarations {
			permSetKeys[nsName{profile.Namespace, decl.PermissionSetRef}] = struct{}{}
		}
		if policy, ok := policyMap[profile.Spec.RBACPolicyRef]; ok {
			permSetKeys[nsName{profile.Namespace, policy.Spec.MaximumPermissionSetRef}] = struct{}{}
		}
	}

	permSetMap := make(map[string]securityv1alpha1.PermissionSet)
	for key := range permSetKeys {
		var ps securityv1alpha1.PermissionSet
		if err := r.Client.Get(ctx, client.ObjectKey{Namespace: key.ns, Name: key.name}, &ps); err != nil {
			if apierrors.IsNotFound(err) {
				logger.Info("EPGReconciler: PermissionSet not found — requeuing",
					"permissionSet", key.name, "namespace", key.ns)
				r.Recorder.Eventf(&securityv1alpha1.PermissionSnapshot{
					ObjectMeta: metav1.ObjectMeta{Name: "epg-error", Namespace: epgSnapshotNamespace},
				}, corev1.EventTypeWarning, "PermissionSetNotFound",
					"EPGReconciler: PermissionSet %q not found; requeue in 15s", key.name)
				return ctrl.Result{RequeueAfter: 15e9}, nil
			}
			return ctrl.Result{}, fmt.Errorf("EPGReconciler: failed to get PermissionSet %s/%s: %w",
				key.ns, key.name, err)
		}
		permSetMap[ps.Name] = ps
	}

	// Step F — Fetch all valid IdentityBindings (IdentityBindingValid=True).
	var bindingList securityv1alpha1.IdentityBindingList
	if err := r.Client.List(ctx, &bindingList); err != nil {
		return ctrl.Result{}, fmt.Errorf("EPGReconciler: failed to list IdentityBindings: %w", err)
	}
	var validBindings []securityv1alpha1.IdentityBinding
	for _, b := range bindingList.Items {
		c := securityv1alpha1.FindCondition(b.Status.Conditions, securityv1alpha1.ConditionTypeIdentityBindingValid)
		if c != nil && c.Status == metav1.ConditionTrue {
			validBindings = append(validBindings, b)
		}
	}

	// Step G — Maps are already built: policyMap and permSetMap.

	// Step H — Call epg.ComputeEPG.
	result, err := epg.ComputeEPG(provisioned, policyMap, permSetMap, validBindings)
	if err != nil {
		logger.Error(err, "EPGReconciler: EPG computation failed — requeuing")
		r.Recorder.Event(
			r.syntheticEventObj(),
			corev1.EventTypeWarning, "EPGComputationFailed",
			fmt.Sprintf("EPGReconciler: computation failed: %v", err),
		)
		return ctrl.Result{RequeueAfter: 15e9}, nil
	}

	// Step I — Upsert PermissionSnapshot for each cluster.
	// First, fetch existing snapshots to preserve existing names.
	var existingSnapshots securityv1alpha1.PermissionSnapshotList
	if err := r.Client.List(ctx, &existingSnapshots, client.InNamespace(epgSnapshotNamespace)); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("EPGReconciler: failed to list existing PermissionSnapshots: %w", err)
	}
	existingByCluster := make(map[string]string)
	for _, sn := range existingSnapshots.Items {
		existingByCluster[sn.Spec.TargetCluster] = sn.Name
	}

	var upsertedSnapshots []*securityv1alpha1.PermissionSnapshot
	for _, cluster := range result.TargetClusters {
		snapshot := epg.BuildPermissionSnapshot(result, cluster, epgSnapshotNamespace, existingByCluster[cluster])

		// Server-side apply to upsert the spec.
		if err := r.Client.Patch(ctx, snapshot, client.Apply, client.ForceOwnership,
			client.FieldOwner(epgFieldOwner)); err != nil {
			return ctrl.Result{}, fmt.Errorf("EPGReconciler: failed to upsert PermissionSnapshot for cluster %s: %w",
				cluster, err)
		}

		// Patch the status subresource.
		// Set ExpectedVersion and Drift=true. Never write LastAckedVersion — that
		// field is owned exclusively by the runner agent in agent mode.
		statusPatch := &securityv1alpha1.PermissionSnapshot{
			TypeMeta: metav1.TypeMeta{
				APIVersion: securityv1alpha1.GroupVersion.String(),
				Kind:       "PermissionSnapshot",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      snapshot.Name,
				Namespace: snapshot.Namespace,
			},
			Status: securityv1alpha1.PermissionSnapshotStatus{
				ExpectedVersion: snapshot.Spec.Version,
				Drift:           true,
				// LastAckedVersion intentionally not set — owned by runner agent.
			},
		}
		if err := r.Client.Status().Patch(ctx, statusPatch, client.Apply, client.ForceOwnership,
			client.FieldOwner(epgFieldOwner)); err != nil {
			return ctrl.Result{}, fmt.Errorf("EPGReconciler: failed to patch PermissionSnapshot status for cluster %s: %w",
				cluster, err)
		}

		upsertedSnapshots = append(upsertedSnapshots, snapshot)
		logger.Info("EPGReconciler: PermissionSnapshot upserted",
			"cluster", cluster, "name", snapshot.Name, "version", snapshot.Spec.Version)
	}

	// Step J — Emit a Normal event on each generated or updated PermissionSnapshot.
	for _, snapshot := range upsertedSnapshots {
		r.Recorder.Eventf(snapshot, corev1.EventTypeNormal, "EPGComputed",
			"EPG computed. Version: %s.", snapshot.Spec.Version)
	}

	// Step K — Emit a Normal event on the management cluster's RunnerConfig.
	// runner.ontai.dev types are not imported into this operator. Unstructured access
	// is used. Skip silently if RunnerConfig is not found (test and bootstrap scenarios).
	if len(result.TargetClusters) > 0 {
		rc := &unstructured.Unstructured{}
		rc.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   "runner.ontai.dev",
			Version: "v1alpha1",
			Kind:    "RunnerConfig",
		})
		if err := r.Client.Get(ctx, types.NamespacedName{Namespace: "ont-system", Name: "management"}, rc); err != nil {
			logger.V(1).Info("EPGReconciler: RunnerConfig not found — skipping EPGRecomputed event",
				"error", err.Error())
		} else {
			msg := fmt.Sprintf("EPG recomputed. %d snapshot(s) written for clusters: %s.",
				len(result.TargetClusters), strings.Join(result.TargetClusters, ", "))
			r.Recorder.Event(rc, corev1.EventTypeNormal, "EPGRecomputed", msg)
		}
	}

	// Step L — Return without requeue.
	logger.Info("EPGReconciler: computation complete",
		"snapshots", len(upsertedSnapshots),
		"clusters", strings.Join(result.TargetClusters, ", "))
	return ctrl.Result{}, nil
}

// reconcileDrift lists all PermissionSnapshots in security-system, computes the
// drift state for each via ReconcileAllDrift, and patches any snapshot whose
// Status.Drift does not match the computed value.
//
// Events are emitted on drift state transitions:
//   - false→true (regression): Warning "SnapshotDriftDetected"
//   - true→false (delivered):  Normal  "SnapshotDelivered"
//
// This method never writes Status.LastAckedVersion — that field is owned
// exclusively by the management cluster conductor receipt observation loop.
func (r *EPGReconciler) reconcileDrift(ctx context.Context) error {
	logger := log.FromContext(ctx)

	var snapshotList securityv1alpha1.PermissionSnapshotList
	if err := r.Client.List(ctx, &snapshotList, client.InNamespace(epgSnapshotNamespace)); err != nil {
		return fmt.Errorf("reconcileDrift: failed to list PermissionSnapshots: %w", err)
	}

	driftResults := ReconcileAllDrift(snapshotList.Items)

	for i, dr := range driftResults {
		sn := &snapshotList.Items[i]

		if sn.Status.Drift == dr.IsDrifted {
			continue // already correct — avoid unnecessary API write
		}

		prevDrift := sn.Status.Drift
		patchBase := client.MergeFrom(sn.DeepCopy())
		sn.Status.Drift = dr.IsDrifted
		if err := r.Client.Status().Patch(ctx, sn, patchBase); err != nil {
			if !apierrors.IsNotFound(err) {
				logger.Error(err, "reconcileDrift: failed to patch Drift on PermissionSnapshot",
					"name", sn.Name)
			}
			continue
		}

		// Emit transition event.
		if dr.IsDrifted && !prevDrift {
			// Regression: snapshot was in sync, now drifted (e.g. agent restarted).
			r.Recorder.Eventf(sn, corev1.EventTypeWarning, "SnapshotDriftDetected",
				"Drift detected: %s.", dr.Reason)
			logger.Info("reconcileDrift: drift regression detected",
				"snapshot", sn.Name, "reason", dr.Reason)
		} else if !dr.IsDrifted && prevDrift {
			// Delivery confirmed: snapshot was drifted, now acknowledged.
			r.Recorder.Eventf(sn, corev1.EventTypeNormal, "SnapshotDelivered",
				"Target cluster acknowledged snapshot version %s.", dr.ExpectedVersion)
			logger.Info("reconcileDrift: snapshot delivered",
				"snapshot", sn.Name, "version", dr.ExpectedVersion)
		}
	}
	return nil
}

// clearAnnotations removes the epg-recompute-requested annotation from all objects
// across all namespaces that currently carry it. This is called BEFORE computation
// begins so that any new signals arriving during computation will be preserved and
// trigger a subsequent run.
func (r *EPGReconciler) clearAnnotations(ctx context.Context) {
	logger := log.FromContext(ctx)

	clearFromList := func(listObj client.ObjectList, items func() []client.Object) {
		if err := r.Client.List(ctx, listObj); err != nil {
			logger.V(1).Info("EPGReconciler: clearAnnotations: failed to list", "error", err.Error())
			return
		}
		for _, obj := range items() {
			if obj.GetAnnotations()[epgRecomputeAnnotation] != "true" {
				continue
			}
			patchBase := client.MergeFrom(obj.DeepCopyObject().(client.Object))
			ann := obj.GetAnnotations()
			delete(ann, epgRecomputeAnnotation)
			obj.SetAnnotations(ann)
			if err := r.Client.Patch(ctx, obj, patchBase); err != nil && !apierrors.IsNotFound(err) {
				logger.V(1).Info("EPGReconciler: clearAnnotations: failed to clear annotation",
					"object", obj.GetName(), "error", err.Error())
			}
		}
	}

	// Clear from RBACProfiles.
	var profiles securityv1alpha1.RBACProfileList
	clearFromList(&profiles, func() []client.Object {
		items := make([]client.Object, len(profiles.Items))
		for i := range profiles.Items {
			items[i] = &profiles.Items[i]
		}
		return items
	})

	// Clear from RBACPolicies.
	var policies securityv1alpha1.RBACPolicyList
	clearFromList(&policies, func() []client.Object {
		items := make([]client.Object, len(policies.Items))
		for i := range policies.Items {
			items[i] = &policies.Items[i]
		}
		return items
	})

	// Clear from IdentityBindings.
	var bindings securityv1alpha1.IdentityBindingList
	clearFromList(&bindings, func() []client.Object {
		items := make([]client.Object, len(bindings.Items))
		for i := range bindings.Items {
			items[i] = &bindings.Items[i]
		}
		return items
	})

	// Clear from PermissionSets.
	var permSets securityv1alpha1.PermissionSetList
	clearFromList(&permSets, func() []client.Object {
		items := make([]client.Object, len(permSets.Items))
		for i := range permSets.Items {
			items[i] = &permSets.Items[i]
		}
		return items
	})
}

// signalRecompute re-annotates an object with epg-recompute-requested=true so that
// it will re-trigger the EPGReconciler after the current run completes.
func (r *EPGReconciler) signalRecompute(ctx context.Context, obj client.Object) {
	patchBase := client.MergeFrom(obj.DeepCopyObject().(client.Object))
	ann := obj.GetAnnotations()
	if ann == nil {
		ann = make(map[string]string)
	}
	ann[epgRecomputeAnnotation] = "true"
	obj.SetAnnotations(ann)
	if err := r.Client.Patch(ctx, obj, patchBase); err != nil && !apierrors.IsNotFound(err) {
		log.FromContext(ctx).V(1).Info("EPGReconciler: failed to re-annotate for recompute",
			"object", obj.GetName(), "error", err.Error())
	}
}

// syntheticEventObj returns a minimal PermissionSnapshot to use as an event target
// when no real snapshot is available (e.g., computation failure before any snapshot exists).
func (r *EPGReconciler) syntheticEventObj() *securityv1alpha1.PermissionSnapshot {
	return &securityv1alpha1.PermissionSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "epg-controller",
			Namespace: epgSnapshotNamespace,
		},
	}
}

// epgRecomputeAnnotationFilter is a predicate that only passes events where the
// ontai.dev/epg-recompute-requested=true annotation is present on the object.
type epgRecomputeAnnotationFilter struct {
	predicate.Funcs
}

func (epgRecomputeAnnotationFilter) Create(e event.CreateEvent) bool {
	return e.Object.GetAnnotations()[epgRecomputeAnnotation] == "true"
}

func (epgRecomputeAnnotationFilter) Update(e event.UpdateEvent) bool {
	return e.ObjectNew.GetAnnotations()[epgRecomputeAnnotation] == "true"
}

func (epgRecomputeAnnotationFilter) Delete(_ event.DeleteEvent) bool   { return false }
func (epgRecomputeAnnotationFilter) Generic(_ event.GenericEvent) bool { return false }

// SetupWithManager registers the EPGReconciler to watch six resource types.
//
// Four watches use the annotation filter and map to the "epg-trigger" fixed key —
// they trigger full EPG recomputation:
//   - RBACProfile (annotation: ontai.dev/epg-recompute-requested)
//   - RBACPolicy
//   - IdentityBinding
//   - PermissionSet
//
// Two watches map to the "drift-check" fixed key — they trigger reconcileDrift only:
//   - PermissionSnapshotReceipt (any create/update: agent acknowledgement arrived)
//   - PermissionSnapshot (any create/update: new snapshot version available)
//
// Multiple simultaneous triggers of the same key collapse into one run via the
// work queue.
func (r *EPGReconciler) SetupWithManager(mgr ctrl.Manager) error {
	filter := epgRecomputeAnnotationFilter{}

	// fixedKey maps any triggering object to the epg-trigger reconcile request.
	fixedKey := handler.EnqueueRequestsFromMapFunc(
		func(_ context.Context, _ client.Object) []reconcile.Request {
			return []reconcile.Request{
				{NamespacedName: types.NamespacedName{
					Namespace: epgSnapshotNamespace,
					Name:      epgTriggerName,
				}},
			}
		},
	)

	// driftKey maps any triggering object to the drift-check reconcile request.
	driftKey := handler.EnqueueRequestsFromMapFunc(
		func(_ context.Context, _ client.Object) []reconcile.Request {
			return []reconcile.Request{
				{NamespacedName: types.NamespacedName{
					Namespace: epgSnapshotNamespace,
					Name:      epgDriftTriggerName,
				}},
			}
		},
	)

	return ctrl.NewControllerManagedBy(mgr).
		// EPG recomputation triggers (annotation-filtered).
		Watches(&securityv1alpha1.RBACProfile{}, fixedKey, builder.WithPredicates(filter)).
		Watches(&securityv1alpha1.RBACPolicy{}, fixedKey, builder.WithPredicates(filter)).
		Watches(&securityv1alpha1.IdentityBinding{}, fixedKey, builder.WithPredicates(filter)).
		Watches(&securityv1alpha1.PermissionSet{}, fixedKey, builder.WithPredicates(filter)).
		// Drift-check triggers (all create/update events, no annotation filter).
		Watches(&securityv1alpha1.PermissionSnapshotReceipt{}, driftKey).
		Watches(&securityv1alpha1.PermissionSnapshot{}, driftKey).
		Named("epg").
		Complete(r)
}
