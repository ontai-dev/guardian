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

// IdentityBindingReconciler watches IdentityBinding CRs, validates them, and
// signals the EPGReconciler when valid.
//
// This is a STUB implementation for Session 4. Full EPG trigger wiring is Session 5.
//
// TODO(session-5): EPG trigger on IdentityBinding change is implemented here as an
// annotation signal. Full EPG recomputation wiring is Session 5.
type IdentityBindingReconciler struct {
	// Client is the controller-runtime client for Kubernetes API access.
	Client client.Client

	// Scheme is the runtime scheme used for object type registration.
	Scheme *runtime.Scheme

	// Recorder is the Kubernetes event recorder for emitting Warning and Normal events.
	Recorder record.EventRecorder
}

// Reconcile is the main reconciliation loop for IdentityBinding.
//
// +kubebuilder:rbac:groups=security.ontai.dev,resources=identitybindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.ontai.dev,resources=identitybindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=identitybindings/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
func (r *IdentityBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the IdentityBinding CR.
	// Not found means the CR was deleted. INV-006: no Jobs on the delete path.
	binding := &securityv1alpha1.IdentityBinding{}
	if err := r.Client.Get(ctx, req.NamespacedName, binding); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("IdentityBinding not found — likely deleted, ignoring", "namespacedName", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get IdentityBinding %s: %w", req.NamespacedName, err)
	}

	// Deferred status patch.
	patchBase := client.MergeFrom(binding.DeepCopy())
	defer func() {
		if err := r.Client.Status().Patch(ctx, binding, patchBase); err != nil {
			if !apierrors.IsNotFound(err) {
				logger.Error(err, "failed to patch IdentityBinding status",
					"name", binding.Name, "namespace", binding.Namespace)
			}
		}
	}()

	// Advance ObservedGeneration.
	binding.Status.ObservedGeneration = binding.Generation

	// Validate the spec.
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

		r.Recorder.Event(binding, corev1.EventTypeWarning, "ValidationFailed", joinedReasons)
		logger.Info("IdentityBinding validation failed",
			"name", binding.Name, "namespace", binding.Namespace)

		return ctrl.Result{}, nil
	}

	binding.Status.ValidationSummary = "Valid."
	securityv1alpha1.SetCondition(
		&binding.Status.Conditions,
		securityv1alpha1.ConditionTypeIdentityBindingValid,
		metav1.ConditionTrue,
		securityv1alpha1.ReasonIdentityBindingValid,
		"IdentityBinding validated successfully.",
		binding.Generation,
	)

	r.Recorder.Event(binding, corev1.EventTypeNormal, "ValidationPassed",
		"IdentityBinding validated successfully.")

	logger.Info("IdentityBinding validated",
		"name", binding.Name, "namespace", binding.Namespace)

	// Annotate with epg-recompute-requested — signals EPGReconciler that this
	// binding has changed and EPG recomputation is needed. The EPGReconciler will
	// clear this annotation after processing.
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
