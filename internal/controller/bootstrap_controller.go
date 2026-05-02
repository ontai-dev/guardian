package controller

import (
	"context"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientevents "k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/webhook"
)

// GuardianSingletonName is the name of the singleton Guardian CR that
// BootstrapController creates and manages. There is exactly one Guardian CR
// per cluster. INV-020.
const GuardianSingletonName = "guardian"

// BootstrapController manages the lifecycle of the singleton Guardian CR and
// drives the admission enforcement mode transitions.
//
// Responsibilities:
//  1. Create the Guardian CR singleton on startup if absent.
//  2. Set WebhookMode=Initialising on the Guardian CR when first created.
//  3. When all RBACProfiles in all namespaces reach Provisioned=True:
//     advance WebhookMode from Initialising to ObserveOnly, and update
//     the in-memory WebhookModeGate.
//  4. For each namespace where all RBACProfiles are Provisioned=True:
//     record the namespace in Guardian.Status.NamespaceEnforcements, and
//     mark it active in the in-memory NamespaceEnforcementRegistry.
//
// The per-namespace enforcement transition is one-way and irreversible.
// The global ObserveOnly transition is one-way: once set, BootstrapController
// never reverts it. INV-020, CS-INV-004.
//
// BootstrapController reconciles on RBACProfile changes (any namespace).
// It reads all RBACProfiles to evaluate global and per-namespace readiness.
type BootstrapController struct {
	Client   client.Client
	Scheme   *runtime.Scheme
	Recorder clientevents.EventRecorder

	// Gate is the in-memory global webhook mode gate shared with the webhook handler.
	Gate *webhook.WebhookModeGate

	// Registry is the in-memory per-namespace enforcement registry shared with the
	// webhook handler via GuardedNamespaceModeResolver.
	Registry *webhook.NamespaceEnforcementRegistry

	// OperatorNamespace is the namespace where the Guardian singleton CR lives and
	// where the operator itself runs. Populated from OPERATOR_NAMESPACE env var.
	OperatorNamespace string

	// SweepDone is set to true by BootstrapAnnotationRunnable when the pre-existing
	// RBAC annotation sweep has completed. BootstrapController blocks the
	// Initialising → ObserveOnly transition until this flag is true.
	// guardian-schema.md §4, INV-020.
	SweepDone *atomic.Bool
}

// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings;clusterroles;clusterrolebindings,verbs=get;list;watch

// SetupWithManager registers BootstrapController with the manager.
// It watches RBACProfile CRs across all namespaces so that any provisioning
// transition triggers re-evaluation of the global and per-namespace gates.
//
// Watches() is used instead of For() to decouple this controller's informer
// registration from RBACProfileReconciler's For(RBACProfile) registration.
// In controller-runtime v0.23.3, two controllers sharing the same GVK informer
// via For() may not both receive events reliably after cache sync.
//
// All RBACProfile events are mapped to a fixed reconcile request for the
// Guardian singleton — BootstrapController reconciles global state, not
// individual RBACProfile objects.
func (r *BootstrapController) SetupWithManager(mgr ctrl.Manager) error {
	singletonKey := handler.EnqueueRequestsFromMapFunc(
		func(_ context.Context, _ client.Object) []reconcile.Request {
			return []reconcile.Request{
				{NamespacedName: types.NamespacedName{
					Namespace: r.OperatorNamespace,
					Name:      GuardianSingletonName,
				}},
			}
		},
	)

	// startupSource enqueues one reconcile request for the Guardian singleton
	// when the controller starts (after the cache is synced). This guarantees
	// the Guardian CR is created and enforcement state is evaluated on startup,
	// independent of whether any RBACProfile events arrive.
	//
	// source.Func.Start is called by controller-runtime exactly once, after the
	// informer cache is ready and the controller goroutine begins.
	startupSource := source.Func(func(_ context.Context, q workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: r.OperatorNamespace,
			Name:      GuardianSingletonName,
		}})
		return nil
	})

	return ctrl.NewControllerManagedBy(mgr).
		Watches(&securityv1alpha1.RBACProfile{}, singletonKey).
		WatchesRawSource(startupSource).
		Named("bootstrap").
		Complete(r)
}

// Reconcile processes an RBACProfile event and re-evaluates the Guardian CR
// enforcement state. It is safe to call concurrently — state transitions are
// idempotent and guarded by status patch conflicts.
func (r *BootstrapController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Ensure the singleton Guardian CR exists.
	gdn := &securityv1alpha1.Guardian{}
	err := r.Client.Get(ctx, types.NamespacedName{
		Name:      GuardianSingletonName,
		Namespace: r.OperatorNamespace,
	}, gdn)
	if apierrors.IsNotFound(err) {
		gdn = r.newGuardianSingleton()
		if createErr := r.Client.Create(ctx, gdn); createErr != nil && !apierrors.IsAlreadyExists(createErr) {
			logger.Error(createErr, "failed to create Guardian singleton")
			return ctrl.Result{}, createErr
		}
		// Refetch after create.
		if getErr := r.Client.Get(ctx, types.NamespacedName{
			Name:      GuardianSingletonName,
			Namespace: r.OperatorNamespace,
		}, gdn); getErr != nil {
			return ctrl.Result{}, getErr
		}
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// List all RBACProfiles across all namespaces.
	profiles := &securityv1alpha1.RBACProfileList{}
	if err := r.Client.List(ctx, profiles); err != nil {
		return ctrl.Result{}, err
	}

	// Evaluate global and per-namespace readiness.
	globalReady, nsReadiness := evaluateReadiness(profiles.Items)

	// Update in-memory gate for per-namespace enforcements.
	// Always update registry for all ready namespaces — idempotent.
	for ns, ready := range nsReadiness {
		if ready {
			r.Registry.SetActive(ns)
		}
	}

	// Capture the mode as it stands at reconcile entry, before any transitions.
	// The Enforcing evaluation block must only run when the mode was ALREADY
	// ObserveOnly at the start of this reconcile — not in the same pass that
	// performs the Initialising → ObserveOnly transition.
	modeAtEntry := gdn.Status.WebhookMode

	// Prepare the updated status patch.
	patch := client.MergeFrom(gdn.DeepCopy())

	// Update NamespaceEnforcements on the Guardian CR.
	if gdn.Status.NamespaceEnforcements == nil {
		gdn.Status.NamespaceEnforcements = make(map[string]bool)
	}
	changed := false
	for ns, ready := range nsReadiness {
		if ready && !gdn.Status.NamespaceEnforcements[ns] {
			gdn.Status.NamespaceEnforcements[ns] = true
			changed = true
		}
	}

	// Advance global WebhookMode from Initialising to ObserveOnly when ready.
	// This transition is one-way: do not revert ObserveOnly or Enforcing.
	//
	// Gate: the annotation sweep (BootstrapAnnotationRunnable) must complete before
	// the mode is advanced. Without a clean annotation baseline, advancing to
	// ObserveOnly may begin per-namespace enforce transitions against unannotated
	// pre-existing resources. guardian-schema.md §4. INV-020.
	if globalReady && gdn.Status.WebhookMode == securityv1alpha1.WebhookModeInitialising &&
		r.SweepDone != nil && !r.SweepDone.Load() {
		logger.Info("annotation sweep not yet complete; requeuing before ObserveOnly advance",
			"requeueAfter", "5s",
		)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	if globalReady && gdn.Status.WebhookMode == securityv1alpha1.WebhookModeInitialising {
		gdn.Status.WebhookMode = securityv1alpha1.WebhookModeObserveOnly
		securityv1alpha1.SetCondition(
			&gdn.Status.Conditions,
			"BootstrapComplete",
			metav1.ConditionTrue,
			securityv1alpha1.ReasonBootstrapProfilesReady,
			"all RBACProfiles provisioned; webhook advancing to ObserveOnly",
			gdn.Generation,
		)
		changed = true
		logger.Info("bootstrap profiles all provisioned; advancing to ObserveOnly")
	} else if !globalReady && gdn.Status.WebhookMode == securityv1alpha1.WebhookModeInitialising {
		securityv1alpha1.SetCondition(
			&gdn.Status.Conditions,
			"BootstrapComplete",
			metav1.ConditionFalse,
			securityv1alpha1.ReasonBootstrapProfilesPending,
			"waiting for all RBACProfiles to reach Provisioned=True",
			gdn.Generation,
		)
		changed = true
	}

	// Evaluate per-namespace Enforcing readiness once ObserveOnly is reached.
	// A namespace is Enforcing-ready when all profiles are provisioned AND all
	// RBAC resources carry ontai.dev/rbac-owner=guardian.
	//
	// This block gates on modeAtEntry — the mode at the START of this reconcile —
	// not the potentially-modified gdn.Status.WebhookMode. This ensures the
	// Initialising → ObserveOnly and ObserveOnly → Enforcing transitions never
	// collapse into a single reconcile. Each transition is patched independently,
	// keeping status history legible and test assertions tractable.
	if modeAtEntry == securityv1alpha1.WebhookModeObserveOnly ||
		modeAtEntry == securityv1alpha1.WebhookModeEnforcing {

		nsEnforcing, clusterReady, enfErr := r.evaluateEnforcingReadiness(ctx, nsReadiness)
		if enfErr != nil {
			return ctrl.Result{}, enfErr
		}

		// Promote namespaces that are Enforcing-ready.
		for ns, ready := range nsEnforcing {
			if ready {
				r.Registry.SetEnforcing(ns)
			}
		}

		// Advance global mode from ObserveOnly to Enforcing when all namespaces
		// with profiles are Enforcing-ready AND cluster-scoped resources are clean.
		// This transition is one-way: once Enforcing, do not revert. INV-020.
		if modeAtEntry == securityv1alpha1.WebhookModeObserveOnly && clusterReady {
			allEnforcing := len(nsEnforcing) > 0
			for _, ready := range nsEnforcing {
				if !ready {
					allEnforcing = false
					break
				}
			}
			if allEnforcing {
				gdn.Status.WebhookMode = securityv1alpha1.WebhookModeEnforcing
				securityv1alpha1.SetCondition(
					&gdn.Status.Conditions,
					"EnforcingComplete",
					metav1.ConditionTrue,
					"AllNamespacesEnforcing",
					"all namespaces RBAC-annotated and profiles provisioned; advancing to Enforcing",
					gdn.Generation,
				)
				changed = true
				logger.Info("all namespaces enforcing-ready; advancing to Enforcing")
			}
		}
	}

	if !changed {
		return ctrl.Result{}, nil
	}

	if err := r.Client.Status().Patch(ctx, gdn, patch); err != nil {
		if apierrors.IsConflict(err) {
			// Conflict on status patch — requeue for re-evaluation.
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}

	// Advance in-memory gate after successful status patch.
	switch gdn.Status.WebhookMode {
	case securityv1alpha1.WebhookModeObserveOnly:
		r.Gate.SetMode(securityv1alpha1.WebhookModeObserveOnly)
	case securityv1alpha1.WebhookModeEnforcing:
		r.Gate.SetMode(securityv1alpha1.WebhookModeEnforcing)
	}

	return ctrl.Result{}, nil
}

// newGuardianSingleton constructs the initial Guardian singleton CR with
// WebhookMode=Initialising. Created on first reconcile if absent.
func (r *BootstrapController) newGuardianSingleton() *securityv1alpha1.Guardian {
	gdn := &securityv1alpha1.Guardian{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianSingletonName,
			Namespace: r.OperatorNamespace,
		},
	}
	gdn.Status.WebhookMode = securityv1alpha1.WebhookModeInitialising
	return gdn
}

// evaluateEnforcingReadiness checks per-namespace and cluster-scoped enforcing
// readiness. A namespace is Enforcing-ready when it is profile-ready (nsReadiness=true)
// AND all its namespaced RBAC resources (Roles, RoleBindings, ServiceAccounts) carry
// the ontai.dev/rbac-owner=guardian annotation. clusterReady is true when all
// ClusterRoles and ClusterRoleBindings carry the annotation.
//
// Only namespaces that are already profile-ready are checked — namespaces not yet
// profile-ready cannot be Enforcing-ready.
func (r *BootstrapController) evaluateEnforcingReadiness(
	ctx context.Context,
	nsReadiness map[string]bool,
) (nsEnforcing map[string]bool, clusterReady bool, err error) {
	nsEnforcing = make(map[string]bool)

	for ns, ready := range nsReadiness {
		if !ready {
			nsEnforcing[ns] = false
			continue
		}
		ok, checkErr := r.isNamespaceAnnotationComplete(ctx, ns)
		if checkErr != nil {
			return nil, false, checkErr
		}
		nsEnforcing[ns] = ok
	}

	clusterReady, err = r.isClusterScopedAnnotationComplete(ctx)
	return nsEnforcing, clusterReady, err
}

// isNamespaceAnnotationComplete returns true when all Roles, RoleBindings, and
// ServiceAccounts in namespace ns carry ontai.dev/rbac-owner=guardian.
func (r *BootstrapController) isNamespaceAnnotationComplete(ctx context.Context, ns string) (bool, error) {
	roleList := &rbacv1.RoleList{}
	if err := r.Client.List(ctx, roleList, client.InNamespace(ns)); err != nil {
		return false, err
	}
	for i := range roleList.Items {
		if roleList.Items[i].Annotations[webhook.AnnotationRBACOwner] != webhook.AnnotationRBACOwnerValue {
			return false, nil
		}
	}

	rbList := &rbacv1.RoleBindingList{}
	if err := r.Client.List(ctx, rbList, client.InNamespace(ns)); err != nil {
		return false, err
	}
	for i := range rbList.Items {
		if rbList.Items[i].Annotations[webhook.AnnotationRBACOwner] != webhook.AnnotationRBACOwnerValue {
			return false, nil
		}
	}

	saList := &corev1.ServiceAccountList{}
	if err := r.Client.List(ctx, saList, client.InNamespace(ns)); err != nil {
		return false, err
	}
	for i := range saList.Items {
		if saList.Items[i].Annotations[webhook.AnnotationRBACOwner] != webhook.AnnotationRBACOwnerValue {
			return false, nil
		}
	}

	return true, nil
}

// isClusterScopedAnnotationComplete returns true when all ClusterRoles and
// ClusterRoleBindings on the cluster carry ontai.dev/rbac-owner=guardian.
func (r *BootstrapController) isClusterScopedAnnotationComplete(ctx context.Context) (bool, error) {
	crList := &rbacv1.ClusterRoleList{}
	if err := r.Client.List(ctx, crList); err != nil {
		return false, err
	}
	for i := range crList.Items {
		if crList.Items[i].Annotations[webhook.AnnotationRBACOwner] != webhook.AnnotationRBACOwnerValue {
			return false, nil
		}
	}

	crbList := &rbacv1.ClusterRoleBindingList{}
	if err := r.Client.List(ctx, crbList); err != nil {
		return false, err
	}
	for i := range crbList.Items {
		if crbList.Items[i].Annotations[webhook.AnnotationRBACOwner] != webhook.AnnotationRBACOwnerValue {
			return false, nil
		}
	}

	return true, nil
}

// evaluateReadiness computes global readiness (all profiles provisioned) and
// per-namespace readiness (all profiles in that namespace provisioned).
// A namespace with zero profiles is NOT considered ready — there must be at
// least one provisioned profile for enforcement to be meaningful.
//
// Returns:
//
//	globalReady: true if there is at least one profile and all are provisioned.
//	nsReadiness: map from namespace to true when all profiles in it are provisioned.
func evaluateReadiness(profiles []securityv1alpha1.RBACProfile) (globalReady bool, nsReadiness map[string]bool) {
	nsReadiness = make(map[string]bool)
	if len(profiles) == 0 {
		return false, nsReadiness
	}

	// Per-namespace tracking: total count and provisioned count.
	type nsState struct {
		total       int
		provisioned int
	}
	states := make(map[string]*nsState)

	for i := range profiles {
		p := &profiles[i]
		ns := p.Namespace
		if states[ns] == nil {
			states[ns] = &nsState{}
		}
		states[ns].total++
		if p.Status.Provisioned {
			states[ns].provisioned++
		}
	}

	allReady := true
	for ns, st := range states {
		ready := st.total > 0 && st.provisioned == st.total
		nsReadiness[ns] = ready
		if !ready {
			allReady = false
		}
	}
	return allReady, nsReadiness
}
