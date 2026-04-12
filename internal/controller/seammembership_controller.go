package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	seamv1alpha1 "github.com/ontai-dev/seam-core/api/v1alpha1"
)

// SeamMembershipReconciler watches SeamMembership CRs in seam-system and
// validates them against the operator's RBACProfile.
//
// Reconcile loop:
//
//	Step A — Fetch SeamMembership. Not found → return nil.
//	Step B — Defer status patch.
//	Step C — Find matching RBACProfile by principalRef. Mismatch → Validated=False.
//	Step D — Verify domainIdentityRef matches RBACProfile.DomainIdentityRef.
//	Step E — Verify RBACProfile.Status.Provisioned == true.
//	Step F — Set Validated=True.
//	Step G — Admit: set Admitted=True, AdmittedAt, PermissionSnapshotRef.
type SeamMembershipReconciler struct {
	// Client is the controller-runtime client for Kubernetes API access.
	Client client.Client

	// Scheme is the runtime scheme used for object type registration.
	Scheme *runtime.Scheme
}

// Reconcile is the main reconciliation loop for SeamMembership.
//
// +kubebuilder:rbac:groups=infrastructure.ontai.dev,resources=seammemberships,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infrastructure.ontai.dev,resources=seammemberships/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=rbacprofiles,verbs=get;list;watch
func (r *SeamMembershipReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Step A — Fetch SeamMembership. Not found means deleted — no action.
	membership := &seamv1alpha1.SeamMembership{}
	if err := r.Client.Get(ctx, req.NamespacedName, membership); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetch SeamMembership %s: %w", req.NamespacedName, err)
	}

	// Step B — Defer status patch. All mutations to membership.Status are
	// persisted via this patch regardless of which return path is taken.
	patchBase := client.MergeFrom(membership.DeepCopy())
	defer func() {
		if err := r.Client.Status().Patch(ctx, membership, patchBase); err != nil {
			if !apierrors.IsNotFound(err) {
				logger.Error(err, "patch SeamMembership status",
					"name", membership.Name, "namespace", membership.Namespace)
			}
		}
	}()

	// Step C — Find the RBACProfile in the same namespace whose principalRef
	// matches membership.Spec.PrincipalRef.
	profileList := &securityv1alpha1.RBACProfileList{}
	if err := r.Client.List(ctx, profileList, client.InNamespace(membership.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list RBACProfiles: %w", err)
	}

	var matchedProfile *securityv1alpha1.RBACProfile
	for i := range profileList.Items {
		if profileList.Items[i].Spec.PrincipalRef == membership.Spec.PrincipalRef {
			matchedProfile = &profileList.Items[i]
			break
		}
	}

	if matchedProfile == nil {
		msg := fmt.Sprintf(
			"no RBACProfile found in namespace %q with principalRef=%q",
			membership.Namespace, membership.Spec.PrincipalRef,
		)
		securityv1alpha1.SetCondition(
			&membership.Status.Conditions,
			seamv1alpha1.ConditionTypeSeamMembershipValidated,
			metav1.ConditionFalse,
			seamv1alpha1.ReasonDomainIdentityMismatch,
			msg,
			membership.Generation,
		)
		membership.Status.Admitted = false
		return ctrl.Result{RequeueAfter: 30e9}, nil // 30 seconds
	}

	// Step D — Verify domainIdentityRef consistency.
	if matchedProfile.Spec.DomainIdentityRef != membership.Spec.DomainIdentityRef {
		msg := fmt.Sprintf(
			"SeamMembership.spec.domainIdentityRef=%q does not match RBACProfile %q domainIdentityRef=%q",
			membership.Spec.DomainIdentityRef,
			matchedProfile.Name,
			matchedProfile.Spec.DomainIdentityRef,
		)
		securityv1alpha1.SetCondition(
			&membership.Status.Conditions,
			seamv1alpha1.ConditionTypeSeamMembershipValidated,
			metav1.ConditionFalse,
			seamv1alpha1.ReasonDomainIdentityMismatch,
			msg,
			membership.Generation,
		)
		membership.Status.Admitted = false
		return ctrl.Result{}, nil
	}

	// Step E — Verify RBACProfile is provisioned.
	if !matchedProfile.Status.Provisioned {
		msg := fmt.Sprintf(
			"RBACProfile %q in namespace %q is not yet provisioned (provisioned=false)",
			matchedProfile.Name, matchedProfile.Namespace,
		)
		securityv1alpha1.SetCondition(
			&membership.Status.Conditions,
			seamv1alpha1.ConditionTypeSeamMembershipValidated,
			metav1.ConditionFalse,
			seamv1alpha1.ReasonRBACProfileNotProvisioned,
			msg,
			membership.Generation,
		)
		membership.Status.Admitted = false
		return ctrl.Result{RequeueAfter: 15e9}, nil // 15 seconds
	}

	// Step F — All checks passed: set Validated=True.
	securityv1alpha1.SetCondition(
		&membership.Status.Conditions,
		seamv1alpha1.ConditionTypeSeamMembershipValidated,
		metav1.ConditionTrue,
		seamv1alpha1.ReasonMembershipAdmitted,
		"All validation checks passed.",
		membership.Generation,
	)

	// Step G — Admit membership.
	// Only advance AdmittedAt on the first transition to Admitted=true.
	if !membership.Status.Admitted {
		now := metav1.Now()
		membership.Status.AdmittedAt = &now
	}
	membership.Status.Admitted = true

	// Resolve PermissionSnapshotRef by tier.
	// infrastructure tier → snapshot-management (the management cluster snapshot).
	// application tier → snapshot-{clusterName} (future: resolved from ClusterAssignment).
	if membership.Spec.Tier == "infrastructure" {
		membership.Status.PermissionSnapshotRef = "snapshot-management"
	} else {
		// application tier: placeholder until ClusterAssignment is resolved in a
		// future session. Uses appIdentityRef as a stable key.
		membership.Status.PermissionSnapshotRef = "snapshot-" + membership.Spec.AppIdentityRef
	}

	securityv1alpha1.SetCondition(
		&membership.Status.Conditions,
		seamv1alpha1.ConditionTypeSeamMembershipAdmitted,
		metav1.ConditionTrue,
		seamv1alpha1.ReasonMembershipAdmitted,
		fmt.Sprintf("Operator %q admitted to the Seam %s family.", membership.Spec.AppIdentityRef, membership.Spec.Tier),
		membership.Generation,
	)

	logger.Info("SeamMembership admitted",
		"name", membership.Name,
		"appIdentityRef", membership.Spec.AppIdentityRef,
		"tier", membership.Spec.Tier)

	return ctrl.Result{}, nil
}

// SetupWithManager registers SeamMembershipReconciler with the manager.
// GenerationChangedPredicate prevents reconciliation on status-only updates.
func (r *SeamMembershipReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&seamv1alpha1.SeamMembership{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
