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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

// rbacPolicyFinalizer is added to every RBACPolicy on first reconcile to ensure
// cleanup events are emitted before the object is fully removed.
// INV-006: deletion triggers events, not Jobs.
const rbacPolicyFinalizer = "security.ontai.dev/rbacpolicy"

// RBACPolicyReconciler watches RBACPolicy CRs and validates their structure.
//
// This reconciler performs in-process validation only. It does not submit Jobs.
// It does not call the Talos API. It does not call the runner shared library for
// Job generation. This is one of the reconcilers in the platform with genuine
// in-process intelligence. INV-002.
//
// Reconcile loop:
//  1. Fetch RBACPolicy CR. Not found → no-op (deletion triggers event, not Job — INV-006).
//  2. Defer status patch.
//  3. Advance ObservedGeneration.
//  4. Call ValidateRBACPolicySpec — pure in-process validation.
//  5. Set conditions and emit events based on validation result.
type RBACPolicyReconciler struct {
	// Client is the controller-runtime client for Kubernetes API access.
	Client client.Client

	// Scheme is the runtime scheme used for object type registration.
	Scheme *runtime.Scheme

	// Recorder is the Kubernetes event recorder for emitting Warning and Normal events.
	Recorder record.EventRecorder
}

// Reconcile is the main reconciliation loop for RBACPolicy.
//
// +kubebuilder:rbac:groups=security.ontai.dev,resources=rbacpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.ontai.dev,resources=rbacpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=rbacpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
func (r *RBACPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Step A — Fetch the RBACPolicy CR.
	// Not found means the CR was deleted. Deletion triggers an event, not a Job.
	// INV-006: no Jobs on the delete path.
	policy := &securityv1alpha1.RBACPolicy{}
	if err := r.Client.Get(ctx, req.NamespacedName, policy); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("RBACPolicy not found — likely deleted, ignoring", "namespacedName", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get RBACPolicy %s: %w", req.NamespacedName, err)
	}

	// Step A2 — Handle deletion. INV-006: emit event, remove finalizer, return. No Job.
	if !policy.DeletionTimestamp.IsZero() {
		r.Recorder.Event(policy, corev1.EventTypeNormal, "Deleting",
			"RBACPolicy is being deleted; releasing finalizer.")
		controllerutil.RemoveFinalizer(policy, rbacPolicyFinalizer)
		if err := r.Client.Update(ctx, policy); err != nil {
			return ctrl.Result{}, fmt.Errorf("remove rbacpolicy finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	// Step A3 — Ensure finalizer is present on first observation.
	if !controllerutil.ContainsFinalizer(policy, rbacPolicyFinalizer) {
		controllerutil.AddFinalizer(policy, rbacPolicyFinalizer)
		if err := r.Client.Update(ctx, policy); err != nil {
			return ctrl.Result{}, fmt.Errorf("add rbacpolicy finalizer: %w", err)
		}
		return ctrl.Result{}, nil // Requeue: the Update triggers a new reconcile.
	}

	// Step B — Set up deferred status patch.
	// The patch base is a deep copy taken before any mutations. The deferred
	// call persists all status mutations made by this reconcile, regardless of
	// which return path is taken.
	patchBase := client.MergeFrom(policy.DeepCopy())
	defer func() {
		if err := r.Client.Status().Patch(ctx, policy, patchBase); err != nil {
			if !apierrors.IsNotFound(err) {
				logger.Error(err, "failed to patch RBACPolicy status",
					"name", policy.Name, "namespace", policy.Namespace)
			}
		}
	}()

	// Step C — Advance ObservedGeneration to the current spec generation.
	policy.Status.ObservedGeneration = policy.Generation

	// Step C2 — Initialize LineageSynced on first observation.
	// One-time write only. The reconciler never updates this condition again.
	// InfrastructureLineageController takes ownership when deployed.
	// seam-core-schema.md §7 Declaration 5.
	if securityv1alpha1.FindCondition(policy.Status.Conditions, securityv1alpha1.ConditionTypeLineageSynced) == nil {
		securityv1alpha1.SetCondition(
			&policy.Status.Conditions,
			securityv1alpha1.ConditionTypeLineageSynced,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonLineageControllerAbsent,
			"InfrastructureLineageController is not yet deployed.",
			policy.Generation,
		)
	}

	// Step D — Validate the spec. Pure in-process — no API calls, no Jobs.
	validationResult := ValidateRBACPolicySpec(policy.Spec)

	// Step D2 — PermissionSet existence check (deferred from Session 3).
	// Structural validation (Step D) already verified MaximumPermissionSetRef is non-empty.
	// Here we verify the referenced PermissionSet CR actually exists.
	// This is a separate concern from structural validation and uses its own condition reason.
	if validationResult.Valid {
		ps := &securityv1alpha1.PermissionSet{}
		psKey := client.ObjectKey{Name: policy.Spec.MaximumPermissionSetRef, Namespace: policy.Namespace}
		if err := r.Client.Get(ctx, psKey, ps); err != nil {
			if apierrors.IsNotFound(err) {
				msg := fmt.Sprintf("PermissionSet %q not found in namespace %q.",
					policy.Spec.MaximumPermissionSetRef, policy.Namespace)
				securityv1alpha1.SetCondition(
					&policy.Status.Conditions,
					securityv1alpha1.ConditionTypeRBACPolicyValid,
					metav1.ConditionFalse,
					securityv1alpha1.ReasonPermissionSetNotFound,
					msg,
					policy.Generation,
				)
				securityv1alpha1.SetCondition(
					&policy.Status.Conditions,
					securityv1alpha1.ConditionTypeRBACPolicyDegraded,
					metav1.ConditionTrue,
					securityv1alpha1.ReasonPermissionSetNotFound,
					msg,
					policy.Generation,
				)
				policy.Status.ValidationSummary = "Waiting: PermissionSet not found."
				r.Recorder.Event(policy, corev1.EventTypeWarning, "PermissionSetNotFound", msg)
				logger.Info("RBACPolicy references missing PermissionSet",
					"name", policy.Name, "namespace", policy.Namespace,
					"permissionSetRef", policy.Spec.MaximumPermissionSetRef)
				// Requeue after 30 seconds — the PermissionSet may be created soon.
				return ctrl.Result{RequeueAfter: 30e9}, nil
			}
			return ctrl.Result{}, fmt.Errorf("failed to get PermissionSet %s: %w", psKey, err)
		}
	}

	// Step E — Handle invalid spec.
	if !validationResult.Valid {
		joinedReasons := strings.Join(validationResult.Reasons, "; ")

		securityv1alpha1.SetCondition(
			&policy.Status.Conditions,
			securityv1alpha1.ConditionTypeRBACPolicyValid,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonValidationFailed,
			joinedReasons,
			policy.Generation,
		)
		securityv1alpha1.SetCondition(
			&policy.Status.Conditions,
			securityv1alpha1.ConditionTypeRBACPolicyDegraded,
			metav1.ConditionTrue,
			securityv1alpha1.ReasonValidationFailed,
			joinedReasons,
			policy.Generation,
		)

		policy.Status.ValidationSummary = fmt.Sprintf(
			"Validation failed: %d check(s) failed.", len(validationResult.FailedChecks))

		r.Recorder.Event(policy, corev1.EventTypeWarning, "ValidationFailed", joinedReasons)

		logger.Info("RBACPolicy validation failed",
			"name", policy.Name, "namespace", policy.Namespace,
			"failedChecks", validationResult.FailedChecks)

		// A structurally invalid policy requires human correction. The reconciler
		// will be re-triggered on the next spec change. No requeue needed.
		return ctrl.Result{}, nil
	}

	// Step F — Handle valid spec.
	securityv1alpha1.SetCondition(
		&policy.Status.Conditions,
		securityv1alpha1.ConditionTypeRBACPolicyValid,
		metav1.ConditionTrue,
		securityv1alpha1.ReasonValidationPassed,
		"Policy structure is valid.",
		policy.Generation,
	)
	securityv1alpha1.SetCondition(
		&policy.Status.Conditions,
		securityv1alpha1.ConditionTypeRBACPolicyDegraded,
		metav1.ConditionFalse,
		securityv1alpha1.ReasonValidationPassed,
		"No degraded conditions.",
		policy.Generation,
	)

	policy.Status.ValidationSummary = "Valid."

	r.Recorder.Event(policy, corev1.EventTypeNormal, "ValidationPassed", "Policy validated successfully.")

	logger.Info("RBACPolicy validated successfully",
		"name", policy.Name, "namespace", policy.Namespace)

	return ctrl.Result{}, nil
}

// SetupWithManager registers RBACPolicyReconciler as the controller for RBACPolicy.
//
// GenerationChangedPredicate prevents reconciliation when only the status
// subresource is updated, breaking the reconcile loop that would otherwise
// be triggered by the reconciler's own status patches.
func (r *RBACPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.RBACPolicy{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
