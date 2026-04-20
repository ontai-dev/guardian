package controller

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientevents "k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

// IdentityBindingReconciler watches IdentityBinding CRs, validates structural
// constraints, resolves the trust anchor IdentityProvider (when IdentityProviderRef
// is set), and signals the EPGReconciler when the binding is fully valid.
//
// Trust anchor resolution: guardian-schema.md §7 — IdentityProvider relationship.
// Session 11: IdentityBinding trust methods implemented (IdentityProvider prerequisite
// satisfied at 5fe5952).
type IdentityBindingReconciler struct {
	// Client is the controller-runtime client for Kubernetes API access.
	Client client.Client

	// Scheme is the runtime scheme used for object type registration.
	Scheme *runtime.Scheme

	// Recorder is the Kubernetes event recorder for emitting Warning and Normal events.
	Recorder clientevents.EventRecorder
}

// Reconcile is the main reconciliation loop for IdentityBinding.
//
// Steps:
//  1. Fetch IdentityBinding. Not found → no-op (INV-006).
//  2. Defer status patch.
//  3. Advance ObservedGeneration.
//  4. Structural validation via ValidateIdentityBindingSpec.
//     If invalid → set IdentityBindingValid=False, return.
//  5. Trust anchor resolution (when IdentityProviderRef is non-empty):
//     a. Fetch IdentityProvider by name in the same namespace.
//     b. Call ResolveIdentityProviderTrust.
//     c. If unresolved → set TrustAnchorResolved=False + IdentityBindingValid=False, return.
//     d. Set TrustAnchorResolved=True.
//  6. Set IdentityBindingValid=True.
//  7. Annotate with epg-recompute-requested.
//
// +kubebuilder:rbac:groups=security.ontai.dev,resources=identitybindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.ontai.dev,resources=identitybindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=identitybindings/finalizers,verbs=update
// +kubebuilder:rbac:groups=security.ontai.dev,resources=identityproviders,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
func (r *IdentityBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Step 1 — Fetch the IdentityBinding CR.
	// Not found means the CR was deleted. INV-006: no Jobs on the delete path.
	binding := &securityv1alpha1.IdentityBinding{}
	if err := r.Client.Get(ctx, req.NamespacedName, binding); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("IdentityBinding not found — likely deleted, ignoring", "namespacedName", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get IdentityBinding %s: %w", req.NamespacedName, err)
	}

	// Step 2 — Deferred status patch.
	patchBase := client.MergeFrom(binding.DeepCopy())
	defer func() {
		if err := r.Client.Status().Patch(ctx, binding, patchBase); err != nil {
			if !apierrors.IsNotFound(err) {
				logger.Error(err, "failed to patch IdentityBinding status",
					"name", binding.Name, "namespace", binding.Namespace)
			}
		}
	}()

	// Step 3 — Advance ObservedGeneration.
	binding.Status.ObservedGeneration = binding.Generation

	// Step 3a — Initialize LineageSynced on first observation.
	// One-time write only. The reconciler never updates this condition again.
	// InfrastructureLineageController takes ownership when deployed.
	// seam-core-schema.md §7 Declaration 5.
	if securityv1alpha1.FindCondition(binding.Status.Conditions, securityv1alpha1.ConditionTypeLineageSynced) == nil {
		securityv1alpha1.SetCondition(
			&binding.Status.Conditions,
			securityv1alpha1.ConditionTypeLineageSynced,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonLineageControllerAbsent,
			"InfrastructureLineageController is not yet deployed.",
			binding.Generation,
		)
	}

	// Step 4 — Structural validation.
	validationResult := ValidateIdentityBindingSpec(binding.Spec)
	if !validationResult.Valid {
		joinedReasons := strings.Join(validationResult.Reasons, "; ")
		binding.Status.ValidationSummary = fmt.Sprintf("Validation failed: %s", joinedReasons)

		securityv1alpha1.SetCondition(
			&binding.Status.Conditions,
			securityv1alpha1.ConditionTypeIdentityBindingValid,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonIdentityBindingInvalid,
			joinedReasons,
			binding.Generation,
		)

		r.Recorder.Eventf(binding, nil, corev1.EventTypeWarning, "ValidationFailed", "ValidationFailed", joinedReasons)
		logger.Info("IdentityBinding validation failed",
			"name", binding.Name, "namespace", binding.Namespace)

		return ctrl.Result{}, nil
	}

	// Step 5 — Trust anchor resolution (when IdentityProviderRef is set).
	if binding.Spec.IdentityProviderRef != "" {
		providerKey := client.ObjectKey{
			Namespace: binding.Namespace,
			Name:      binding.Spec.IdentityProviderRef,
		}
		var provider *securityv1alpha1.IdentityProvider
		fetched := &securityv1alpha1.IdentityProvider{}
		if err := r.Client.Get(ctx, providerKey, fetched); err != nil {
			if !apierrors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("failed to get IdentityProvider %s: %w", providerKey, err)
			}
			// Not found — provider is nil; ResolveIdentityProviderTrust will handle it.
		} else {
			provider = fetched
		}

		trust := ResolveIdentityProviderTrust(binding.Spec.IdentityType, binding.Spec.IdentityProviderRef, provider)

		if !trust.Resolved {
			binding.Status.ValidationSummary = fmt.Sprintf("Trust anchor unresolved: %s", trust.Message)

			securityv1alpha1.SetCondition(
				&binding.Status.Conditions,
				securityv1alpha1.ConditionTypeIdentityBindingTrustAnchorResolved,
				metav1.ConditionFalse,
				trust.Reason,
				trust.Message,
				binding.Generation,
			)
			securityv1alpha1.SetCondition(
				&binding.Status.Conditions,
				securityv1alpha1.ConditionTypeIdentityBindingValid,
				metav1.ConditionFalse,
				trust.Reason,
				trust.Message,
				binding.Generation,
			)

			r.Recorder.Eventf(binding, nil, corev1.EventTypeWarning, "TrustAnchorUnresolved", "TrustAnchorUnresolved", trust.Message)
			logger.Info("IdentityBinding trust anchor unresolved",
				"name", binding.Name, "namespace", binding.Namespace,
				"reason", trust.Reason, "message", trust.Message)

			return ctrl.Result{}, nil
		}

		// Trust anchor resolved successfully.
		securityv1alpha1.SetCondition(
			&binding.Status.Conditions,
			securityv1alpha1.ConditionTypeIdentityBindingTrustAnchorResolved,
			metav1.ConditionTrue,
			trust.Reason,
			trust.Message,
			binding.Generation,
		)
		logger.Info("IdentityBinding trust anchor resolved",
			"name", binding.Name, "provider", binding.Spec.IdentityProviderRef)
	}

	// Step 6 — All checks passed. Set IdentityBindingValid=True.
	binding.Status.ValidationSummary = "Valid."
	securityv1alpha1.SetCondition(
		&binding.Status.Conditions,
		securityv1alpha1.ConditionTypeIdentityBindingValid,
		metav1.ConditionTrue,
		securityv1alpha1.ReasonIdentityBindingValid,
		"IdentityBinding validated successfully.",
		binding.Generation,
	)

	r.Recorder.Eventf(binding, nil, corev1.EventTypeNormal, "ValidationPassed", "ValidationPassed",
		"IdentityBinding validated successfully.")

	logger.Info("IdentityBinding validated",
		"name", binding.Name, "namespace", binding.Namespace)

	// Step 7 — Annotate with epg-recompute-requested — signals EPGReconciler that
	// this binding has changed and EPG recomputation is needed.
	//
	// Use a deep copy to avoid overwriting the in-memory status mutations that
	// the deferred status patch will apply.
	epgBase := binding.DeepCopy()
	epgTarget := binding.DeepCopy()
	if epgTarget.Annotations == nil {
		epgTarget.Annotations = make(map[string]string)
	}
	epgTarget.Annotations[epgRecomputeAnnotation] = "true"
	if err := r.Client.Patch(ctx, epgTarget, client.MergeFrom(epgBase)); err != nil {
		if !apierrors.IsNotFound(err) {
			logger.Error(err, "failed to annotate IdentityBinding with epg-recompute-requested",
				"name", binding.Name, "namespace", binding.Namespace)
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers IdentityBindingReconciler as the controller for IdentityBinding.
func (r *IdentityBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.IdentityBinding{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
