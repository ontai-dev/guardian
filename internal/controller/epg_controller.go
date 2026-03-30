package controller

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/ontai-dev/ont-security/api/v1alpha1"
)

// EPGReconciler watches RBACProfile, RBACPolicy, IdentityBinding, and PermissionSet.
// It is triggered when the ontai.dev/epg-recompute-requested=true annotation is present.
//
// This is a STUB implementation for Session 4.
//
// TODO(session-5): implement full EPG computation.
// Inputs: all RBACProfiles (provisioned=true only), their RBACPolicies,
// all IdentityBindings (valid only), all PermissionSets.
// Output: PermissionSnapshot per target cluster.
// Algorithm: ont-security-design.md Section 2.
type EPGReconciler struct {
	// Client is the controller-runtime client for Kubernetes API access.
	Client client.Client

	// Scheme is the runtime scheme used for object type registration.
	Scheme *runtime.Scheme

	// Recorder is the Kubernetes event recorder for emitting events.
	Recorder record.EventRecorder
}

// Reconcile is the stub reconciliation loop for the EPGReconciler.
//
// When triggered: reads the epg-recompute-requested annotation on the triggering
// object. If present: logs and removes the annotation. Does not compute the EPG.
// Does not create PermissionSnapshot. Does not error.
//
// +kubebuilder:rbac:groups=security.ontai.dev,resources=rbacprofiles,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=rbacpolicies,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=identitybindings,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=permissionsets,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=permissionsnapshots,verbs=get;list;watch;create;update;patch;delete
func (r *EPGReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Try to find the triggering object and clear the annotation.
	// The EPGReconciler is triggered by annotation on any of four types.
	cleared := false

	// Try RBACProfile.
	if !cleared {
		profile := &securityv1alpha1.RBACProfile{}
		if err := r.Client.Get(ctx, req.NamespacedName, profile); err == nil {
			if v, ok := profile.Annotations[epgRecomputeAnnotation]; ok && v == "true" {
				logger.Info("EPG recomputation requested — deferred to Session 5 implementation",
					"resource", "RBACProfile",
					"name", req.Name, "namespace", req.Namespace)
				patchBase := client.MergeFrom(profile.DeepCopy())
				delete(profile.Annotations, epgRecomputeAnnotation)
				if err := r.Client.Patch(ctx, profile, patchBase); err != nil && !apierrors.IsNotFound(err) {
					logger.Error(err, "failed to clear epg-recompute annotation on RBACProfile")
				}
				cleared = true
			}
		}
	}

	// Try IdentityBinding.
	if !cleared {
		binding := &securityv1alpha1.IdentityBinding{}
		if err := r.Client.Get(ctx, req.NamespacedName, binding); err == nil {
			if v, ok := binding.Annotations[epgRecomputeAnnotation]; ok && v == "true" {
				logger.Info("EPG recomputation requested — deferred to Session 5 implementation",
					"resource", "IdentityBinding",
					"name", req.Name, "namespace", req.Namespace)
				patchBase := client.MergeFrom(binding.DeepCopy())
				delete(binding.Annotations, epgRecomputeAnnotation)
				if err := r.Client.Patch(ctx, binding, patchBase); err != nil && !apierrors.IsNotFound(err) {
					logger.Error(err, "failed to clear epg-recompute annotation on IdentityBinding")
				}
				cleared = true
			}
		}
	}

	// Try PermissionSet.
	if !cleared {
		ps := &securityv1alpha1.PermissionSet{}
		if err := r.Client.Get(ctx, req.NamespacedName, ps); err == nil {
			if v, ok := ps.Annotations[epgRecomputeAnnotation]; ok && v == "true" {
				logger.Info("EPG recomputation requested — deferred to Session 5 implementation",
					"resource", "PermissionSet",
					"name", req.Name, "namespace", req.Namespace)
				patchBase := client.MergeFrom(ps.DeepCopy())
				delete(ps.Annotations, epgRecomputeAnnotation)
				if err := r.Client.Patch(ctx, ps, patchBase); err != nil && !apierrors.IsNotFound(err) {
					logger.Error(err, "failed to clear epg-recompute annotation on PermissionSet")
				}
				cleared = true
			}
		}
	}

	// Try RBACPolicy.
	if !cleared {
		policy := &securityv1alpha1.RBACPolicy{}
		if err := r.Client.Get(ctx, req.NamespacedName, policy); err == nil {
			if v, ok := policy.Annotations[epgRecomputeAnnotation]; ok && v == "true" {
				logger.Info("EPG recomputation requested — deferred to Session 5 implementation",
					"resource", "RBACPolicy",
					"name", req.Name, "namespace", req.Namespace)
				patchBase := client.MergeFrom(policy.DeepCopy())
				delete(policy.Annotations, epgRecomputeAnnotation)
				if err := r.Client.Patch(ctx, policy, patchBase); err != nil && !apierrors.IsNotFound(err) {
					logger.Error(err, "failed to clear epg-recompute annotation on RBACPolicy")
				}
			}
		}
	}

	return ctrl.Result{}, nil
}

// epgRecomputeAnnotationFilter is a predicate that only passes events where the
// ontai.dev/epg-recompute-requested=true annotation is present on the object.
// This means the EPGReconciler is only triggered when a sibling reconciler has
// explicitly requested recomputation.
type epgRecomputeAnnotationFilter struct {
	predicate.Funcs
}

func (epgRecomputeAnnotationFilter) Create(e event.CreateEvent) bool {
	return e.Object.GetAnnotations()[epgRecomputeAnnotation] == "true"
}

func (epgRecomputeAnnotationFilter) Update(e event.UpdateEvent) bool {
	return e.ObjectNew.GetAnnotations()[epgRecomputeAnnotation] == "true"
}

func (epgRecomputeAnnotationFilter) Delete(_ event.DeleteEvent) bool { return false }

func (epgRecomputeAnnotationFilter) Generic(_ event.GenericEvent) bool { return false }

// SetupWithManager registers the EPGReconciler to watch four resource types.
// Each watch uses a filter that only enqueues when ontai.dev/epg-recompute-requested=true
// is present on the object.
func (r *EPGReconciler) SetupWithManager(mgr ctrl.Manager) error {
	filter := epgRecomputeAnnotationFilter{}
	return ctrl.NewControllerManagedBy(mgr).
		Watches(
			&securityv1alpha1.RBACProfile{},
			&handler.EnqueueRequestForObject{},
			builder.WithPredicates(filter),
		).
		Watches(
			&securityv1alpha1.RBACPolicy{},
			&handler.EnqueueRequestForObject{},
			builder.WithPredicates(filter),
		).
		Watches(
			&securityv1alpha1.IdentityBinding{},
			&handler.EnqueueRequestForObject{},
			builder.WithPredicates(filter),
		).
		Watches(
			&securityv1alpha1.PermissionSet{},
			&handler.EnqueueRequestForObject{},
			builder.WithPredicates(filter),
		).
		Named("epg").
		Complete(r)
}
