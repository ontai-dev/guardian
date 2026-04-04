package controller

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

// PermissionSetReconciler watches PermissionSet CRs, validates their spec, maintains
// ProfileReferenceCount, and signals the EPGReconciler when the set changes.
//
// ProfileReferenceCount is computed by listing all RBACProfiles across all namespaces
// and counting how many reference this PermissionSet by name. This counter is
// informational only (it does not block provisioning or EPG computation).
//
// Reconcile loop:
//  1. Fetch PermissionSet. Not found → no-op (INV-006).
//  2. Defer status patch.
//  3. Advance ObservedGeneration.
//  4. Call ValidatePermissionSetSpec — pure structural validation.
//  5. If invalid: set PermissionSetValid=False, emit Warning, return.
//  6. Set PermissionSetValid=True.
//  7. Count ProfileReferenceCount by listing all RBACProfiles.
//  8. Annotate with epg-recompute-requested.
//
// +kubebuilder:rbac:groups=security.ontai.dev,resources=permissionsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.ontai.dev,resources=permissionsets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=permissionsets/finalizers,verbs=update
// +kubebuilder:rbac:groups=security.ontai.dev,resources=rbacprofiles,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
type PermissionSetReconciler struct {
	// Client is the controller-runtime client for Kubernetes API access.
	Client client.Client

	// Scheme is the runtime scheme used for object type registration.
	Scheme *runtime.Scheme

	// Recorder is the Kubernetes event recorder for emitting Warning and Normal events.
	Recorder record.EventRecorder
}

// Reconcile is the main reconciliation loop for PermissionSet.
func (r *PermissionSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Step 1 — Fetch the PermissionSet CR.
	ps := &securityv1alpha1.PermissionSet{}
	if err := r.Client.Get(ctx, req.NamespacedName, ps); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("PermissionSet not found — likely deleted, ignoring",
				"namespacedName", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get PermissionSet %s: %w", req.NamespacedName, err)
	}

	// Step 2 — Deferred status patch.
	patchBase := client.MergeFrom(ps.DeepCopy())
	defer func() {
		if err := r.Client.Status().Patch(ctx, ps, patchBase); err != nil {
			if !apierrors.IsNotFound(err) {
				logger.Error(err, "failed to patch PermissionSet status",
					"name", ps.Name, "namespace", ps.Namespace)
			}
		}
	}()

	// Step 3 — Advance ObservedGeneration.
	ps.Status.ObservedGeneration = ps.Generation

	// Step 4 — Structural validation.
	result := ValidatePermissionSetSpec(ps.Spec)
	if !result.Valid {
		joinedReasons := strings.Join(result.Reasons, "; ")

		securityv1alpha1.SetCondition(
			&ps.Status.Conditions,
			securityv1alpha1.ConditionTypePermissionSetValid,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonPermissionSetInvalid,
			joinedReasons,
			ps.Generation,
		)

		r.Recorder.Event(ps, corev1.EventTypeWarning, "ValidationFailed", joinedReasons)
		logger.Info("PermissionSet validation failed",
			"name", ps.Name, "namespace", ps.Namespace, "reasons", joinedReasons)

		return ctrl.Result{}, nil
	}

	// Step 5 — Validation passed.
	securityv1alpha1.SetCondition(
		&ps.Status.Conditions,
		securityv1alpha1.ConditionTypePermissionSetValid,
		metav1.ConditionTrue,
		securityv1alpha1.ReasonPermissionSetValid,
		"PermissionSet spec is valid.",
		ps.Generation,
	)

	// Step 6 — Compute ProfileReferenceCount.
	// List all RBACProfiles across all namespaces and count how many reference this
	// PermissionSet by name in any of their PermissionDeclarations.
	var profileList securityv1alpha1.RBACProfileList
	if err := r.Client.List(ctx, &profileList); err != nil {
		return ctrl.Result{}, fmt.Errorf("PermissionSetReconciler: failed to list RBACProfiles: %w", err)
	}

	count := int32(0)
	for _, profile := range profileList.Items {
		for _, decl := range profile.Spec.PermissionDeclarations {
			if decl.PermissionSetRef == ps.Name {
				count++
				break // count each profile at most once per PermissionSet
			}
		}
	}
	ps.Status.ProfileReferenceCount = count

	logger.Info("PermissionSet reconciled",
		"name", ps.Name, "namespace", ps.Namespace, "profileReferenceCount", count)

	r.Recorder.Event(ps, corev1.EventTypeNormal, "Validated",
		fmt.Sprintf("PermissionSet is valid. ProfileReferenceCount=%d.", count))

	// Step 7 — Annotate with epg-recompute-requested.
	// PermissionSet changes directly affect EPG computation — the ceiling may have
	// changed, or declared permissions in profiles may have changed.
	epgBase := ps.DeepCopy()
	epgTarget := ps.DeepCopy()
	if epgTarget.Annotations == nil {
		epgTarget.Annotations = make(map[string]string)
	}
	epgTarget.Annotations[epgRecomputeAnnotation] = "true"
	if err := r.Client.Patch(ctx, epgTarget, client.MergeFrom(epgBase)); err != nil {
		if !apierrors.IsNotFound(err) {
			logger.Error(err, "failed to annotate PermissionSet with epg-recompute-requested",
				"name", ps.Name, "namespace", ps.Namespace)
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers PermissionSetReconciler as the controller for PermissionSet.
func (r *PermissionSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.PermissionSet{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
