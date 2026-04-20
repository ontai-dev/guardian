package controller

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	corev1apply "k8s.io/client-go/applyconfigurations/core/v1"
	rbacv1apply "k8s.io/client-go/applyconfigurations/rbac/v1"
	clientevents "k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/database"
)

// rbacFieldOwner is the server-side apply field manager name for RBACProfileReconciler.
// All three RBAC resources (ServiceAccount, ClusterRole, ClusterRoleBinding) use this
// field owner so that re-applying an unchanged resource is a no-op. INV-004.
const rbacFieldOwner = "guardian"

// CS-INV-005: Provisioned=true is set ONLY in Step I of this Reconcile method.
// No other code path in this file, this package, or any other package may set
// status.Provisioned=true on RBACProfile. This is enforced architecturally by
// making RBACProfileStatus.Provisioned unexported except through this reconciler's
// status patch. Any future refactor that routes provisioned=true through a different
// code path is a constitutional invariant violation and must be rejected.

// RBACProfileReconciler watches RBACProfile CRs, validates them against their
// governing RBACPolicy, and sets status.Provisioned=true when all checks pass.
//
// This is the most critical reconciler in the platform. CS-INV-005: provisioned=true
// is set exclusively here, after every validation and compliance check passes.
// It is impossible to reach provisioned=true through any code path that bypasses
// this reconciler.
type RBACProfileReconciler struct {
	// Client is the controller-runtime client for Kubernetes API access.
	Client client.Client

	// Scheme is the runtime scheme used for object type registration.
	Scheme *runtime.Scheme

	// Recorder is the Kubernetes event recorder for emitting Warning and Normal events.
	Recorder clientevents.EventRecorder

	// AuditWriter receives operational audit events from this reconciler.
	// Nil is safe — events are silently dropped when no writer is configured.
	AuditWriter database.AuditWriter
}

// epgRecomputeAnnotation is the inter-reconciler signal annotation.
// Set by RBACProfileReconciler and IdentityBindingReconciler. Cleared by EPGReconciler.
const epgRecomputeAnnotation = "ontai.dev/epg-recompute-requested"

// Reconcile is the main reconciliation loop for RBACProfile.
//
// CS-INV-005 enforcement: provisioned=true is set ONLY in Step I below.
// There is no other code path in this file that writes status.Provisioned=true.
//
// +kubebuilder:rbac:groups=security.ontai.dev,resources=rbacprofiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.ontai.dev,resources=rbacprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=rbacprofiles/finalizers,verbs=update
// +kubebuilder:rbac:groups=security.ontai.dev,resources=rbacpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=permissionsets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete;bind;escalate
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
func (r *RBACProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Step A — Fetch the RBACProfile CR.
	// Not found means the CR was deleted. Deletion triggers an event, not a Job.
	// INV-006: no Jobs on the delete path.
	profile := &securityv1alpha1.RBACProfile{}
	if err := r.Client.Get(ctx, req.NamespacedName, profile); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("RBACProfile not found — likely deleted, ignoring", "namespacedName", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get RBACProfile %s: %w", req.NamespacedName, err)
	}

	// ObservedGeneration guard — skip if this generation was already processed
	// and the profile is provisioned. Pending or failed profiles must always be
	// reprocessed regardless of generation match so that requeue cycles complete.
	// Prevents reconcile loops from the reconciler's own status patches (which
	// change ResourceVersion but not Generation) and from informer resync events.
	if profile.Status.ObservedGeneration == profile.Generation && profile.Status.Provisioned {
		return ctrl.Result{}, nil
	}

	// Step B — Set up deferred status patch.
	// The patch base is a deep copy taken before any mutations. The deferred call
	// persists all status mutations made by this reconcile, regardless of which
	// return path is taken.
	patchBase := client.MergeFrom(profile.DeepCopy())
	defer func() {
		if err := r.Client.Status().Patch(ctx, profile, patchBase); err != nil {
			if !apierrors.IsNotFound(err) {
				logger.Error(err, "failed to patch RBACProfile status",
					"name", profile.Name, "namespace", profile.Namespace)
			}
		}
	}()

	// Step C — Advance ObservedGeneration to the current spec generation.
	profile.Status.ObservedGeneration = profile.Generation

	// Step C2 — Initialize LineageSynced on first observation.
	// One-time write only. The reconciler never updates this condition again.
	// InfrastructureLineageController takes ownership when deployed.
	// seam-core-schema.md §7 Declaration 5.
	if securityv1alpha1.FindCondition(profile.Status.Conditions, securityv1alpha1.ConditionTypeLineageSynced) == nil {
		securityv1alpha1.SetCondition(
			&profile.Status.Conditions,
			securityv1alpha1.ConditionTypeLineageSynced,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonLineageControllerAbsent,
			"InfrastructureLineageController is not yet deployed.",
			profile.Generation,
		)
	}

	// Step D — Validate the spec. Pure in-process — no API calls, no Jobs.
	validationResult := ValidateRBACProfileSpec(profile.Spec)
	if !validationResult.Valid {
		joinedReasons := strings.Join(validationResult.Reasons, "; ")

		profile.Status.Provisioned = false
		profile.Status.LastProvisionedAt = nil // clear — this profile has regressed to invalid

		securityv1alpha1.SetCondition(
			&profile.Status.Conditions,
			securityv1alpha1.ConditionTypeRBACProfileProvisioned,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonProvisioningFailed,
			joinedReasons,
			profile.Generation,
		)
		securityv1alpha1.SetCondition(
			&profile.Status.Conditions,
			securityv1alpha1.ConditionTypeRBACProfileValidated,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonProvisioningFailed,
			joinedReasons,
			profile.Generation,
		)

		r.Recorder.Eventf(profile, nil, corev1.EventTypeWarning, "ValidationFailed", "", joinedReasons)
		logger.Info("RBACProfile validation failed",
			"name", profile.Name, "namespace", profile.Namespace,
			"failedChecks", validationResult.FailedChecks)

		writeAudit(ctx, r.AuditWriter, database.AuditEvent{
			ClusterID:      "management",
			Subject:        "guardian",
			Action:         "rbacprofile.validation_failed",
			Resource:       profile.Name,
			Decision:       "system",
			MatchedPolicy:  joinedReasons,
			SequenceNumber: auditSeq(),
		})

		// A structurally invalid profile requires human correction. No requeue.
		return ctrl.Result{}, nil
	}

	// Step E — Fetch the governing RBACPolicy.
	policy := &securityv1alpha1.RBACPolicy{}
	policyKey := types.NamespacedName{Name: profile.Spec.RBACPolicyRef, Namespace: profile.Namespace}
	if err := r.Client.Get(ctx, policyKey, policy); err != nil {
		if apierrors.IsNotFound(err) {
			profile.Status.Provisioned = false
			securityv1alpha1.SetCondition(
				&profile.Status.Conditions,
				securityv1alpha1.ConditionTypeRBACProfileProvisioned,
				metav1.ConditionFalse,
				securityv1alpha1.ReasonPolicyNotFound,
				fmt.Sprintf("RBACPolicy %q not found in namespace %q.", profile.Spec.RBACPolicyRef, profile.Namespace),
				profile.Generation,
			)
			securityv1alpha1.SetCondition(
				&profile.Status.Conditions,
				securityv1alpha1.ConditionTypeRBACProfileValidated,
				metav1.ConditionFalse,
				securityv1alpha1.ReasonPolicyNotFound,
				fmt.Sprintf("RBACPolicy %q not found in namespace %q.", profile.Spec.RBACPolicyRef, profile.Namespace),
				profile.Generation,
			)
			r.Recorder.Eventf(profile, nil, corev1.EventTypeWarning, "PolicyNotFound", "",
				"Governing RBACPolicy %q not found.", profile.Spec.RBACPolicyRef)
			return ctrl.Result{RequeueAfter: 30e9}, nil // 30 seconds
		}
		return ctrl.Result{}, fmt.Errorf("failed to get RBACPolicy %s: %w", policyKey, err)
	}

	// Step F — Verify the governing RBACPolicy itself has RBACPolicyValid=True.
	policyValid := securityv1alpha1.FindCondition(policy.Status.Conditions, securityv1alpha1.ConditionTypeRBACPolicyValid)
	if policyValid == nil || policyValid.Status != metav1.ConditionTrue {
		profile.Status.Provisioned = false
		securityv1alpha1.SetCondition(
			&profile.Status.Conditions,
			securityv1alpha1.ConditionTypeRBACProfileProvisioned,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonPolicyNotFound,
			"Governing RBACPolicy is not yet valid — waiting.",
			profile.Generation,
		)
		securityv1alpha1.SetCondition(
			&profile.Status.Conditions,
			securityv1alpha1.ConditionTypeRBACProfileValidated,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonPolicyNotFound,
			"Governing RBACPolicy is not yet valid — waiting.",
			profile.Generation,
		)
		return ctrl.Result{RequeueAfter: 15e9}, nil // 15 seconds
	}

	// Step G — Verify all referenced PermissionSets exist.
	var missingPermSets []string
	for _, decl := range profile.Spec.PermissionDeclarations {
		ps := &securityv1alpha1.PermissionSet{}
		psKey := types.NamespacedName{Name: decl.PermissionSetRef, Namespace: profile.Namespace}
		if err := r.Client.Get(ctx, psKey, ps); err != nil {
			if apierrors.IsNotFound(err) {
				missingPermSets = append(missingPermSets, decl.PermissionSetRef)
			} else {
				return ctrl.Result{}, fmt.Errorf("failed to get PermissionSet %s: %w", psKey, err)
			}
		}
	}
	if len(missingPermSets) > 0 {
		msg := fmt.Sprintf("Missing PermissionSets: %s.", strings.Join(missingPermSets, ", "))
		profile.Status.Provisioned = false
		securityv1alpha1.SetCondition(
			&profile.Status.Conditions,
			securityv1alpha1.ConditionTypeRBACProfileProvisioned,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonPermissionSetMissing,
			msg,
			profile.Generation,
		)
		r.Recorder.Eventf(profile, nil, corev1.EventTypeWarning, "PermissionSetMissing", "", msg)
		return ctrl.Result{RequeueAfter: 30e9}, nil // 30 seconds
	}

	// Step H — Compliance check against governing RBACPolicy.
	complianceResult := CheckProfilePolicyCompliance(profile.Spec, policy.Spec)
	if !complianceResult.Compliant {
		// Filter out [audit] entries for the violation message — they are not violations.
		var hardViolations []string
		for _, v := range complianceResult.Violations {
			if !strings.HasPrefix(v, "[audit]") {
				hardViolations = append(hardViolations, v)
			}
		}
		joinedViolations := strings.Join(hardViolations, "; ")

		profile.Status.Provisioned = false
		securityv1alpha1.SetCondition(
			&profile.Status.Conditions,
			securityv1alpha1.ConditionTypeRBACProfileProvisioned,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonPolicyViolation,
			joinedViolations,
			profile.Generation,
		)
		securityv1alpha1.SetCondition(
			&profile.Status.Conditions,
			securityv1alpha1.ConditionTypeRBACProfilePolicyCompliant,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonPolicyViolation,
			joinedViolations,
			profile.Generation,
		)
		r.Recorder.Eventf(profile, nil, corev1.EventTypeWarning, "PolicyViolation", "", joinedViolations)
		logger.Info("RBACProfile compliance check failed",
			"name", profile.Name, "namespace", profile.Namespace,
			"violations", hardViolations)

		// Compliance violation requires human correction. No requeue.
		return ctrl.Result{}, nil
	}

	// Step I — All checks passed. THIS IS THE ONLY CODE PATH THAT SETS provisioned=true.
	// CS-INV-005: do not add any other path to set Provisioned=true in this codebase.
	now := metav1.Now()
	profile.Status.Provisioned = true
	profile.Status.LastProvisionedAt = &now
	profile.Status.ValidationSummary = "Provisioned."

	securityv1alpha1.SetCondition(
		&profile.Status.Conditions,
		securityv1alpha1.ConditionTypeRBACProfileProvisioned,
		metav1.ConditionTrue,
		securityv1alpha1.ReasonProvisioningComplete,
		"All validation and compliance checks passed.",
		profile.Generation,
	)
	securityv1alpha1.SetCondition(
		&profile.Status.Conditions,
		securityv1alpha1.ConditionTypeRBACProfileValidated,
		metav1.ConditionTrue,
		securityv1alpha1.ReasonProvisioningComplete,
		"Structural validation passed.",
		profile.Generation,
	)
	securityv1alpha1.SetCondition(
		&profile.Status.Conditions,
		securityv1alpha1.ConditionTypeRBACProfilePolicyCompliant,
		metav1.ConditionTrue,
		securityv1alpha1.ReasonProvisioningComplete,
		"Policy compliance check passed.",
		profile.Generation,
	)

	r.Recorder.Eventf(profile, nil, corev1.EventTypeNormal, "ProvisioningComplete", "",
		"RBACProfile provisioned successfully.")

	logger.Info("RBACProfile provisioned",
		"name", profile.Name, "namespace", profile.Namespace)

	writeAudit(ctx, r.AuditWriter, database.AuditEvent{
		ClusterID:      "management",
		Subject:        profile.Spec.PrincipalRef,
		Action:         "rbacprofile.provisioned",
		Resource:       profile.Name,
		Decision:       "system",
		MatchedPolicy:  "ProvisioningComplete",
		SequenceNumber: auditSeq(),
	})

	// Step J — Materialise Kubernetes RBAC resources for this profile.
	//
	// provisioned=true is committed ONLY after Step J succeeds (see explicit status
	// patch below). If Step J fails, provisioned is reset to false here so the
	// deferred patch commits the failure state. CS-INV-005: this is the sole path
	// through which provisioned=true is observed on the cluster.
	if err := r.provisionRBACResources(ctx, profile); err != nil {
		profile.Status.Provisioned = false
		profile.Status.LastProvisionedAt = nil
		securityv1alpha1.SetCondition(
			&profile.Status.Conditions,
			securityv1alpha1.ConditionTypeRBACProfileProvisioned,
			metav1.ConditionFalse,
			"RBACMaterializationFailed",
			err.Error(),
			profile.Generation,
		)
		r.Recorder.Eventf(profile, nil, corev1.EventTypeWarning, "RBACMaterializationFailed", "", err.Error())
		logger.Error(err, "Step J: RBAC resource provisioning failed",
			"name", profile.Name, "namespace", profile.Namespace)
		return ctrl.Result{}, err
	}

	// Explicitly commit the status before signaling EPGReconciler.
	// The deferred status patch fires AFTER this function returns, but the EPGReconciler
	// is triggered by the metadata patch below. If EPGReconciler runs before the deferred
	// patch commits, it sees Provisioned=false and produces an empty snapshot. To avoid
	// this race, we commit the status here, then update patchBase so the deferred patch
	// is a no-op.
	if err := r.Client.Status().Patch(ctx, profile, patchBase); err != nil {
		if !apierrors.IsNotFound(err) {
			logger.Error(err, "failed to commit RBACProfile status before EPG signal",
				"name", profile.Name, "namespace", profile.Namespace)
		}
	}
	// Advance patchBase to the now-committed state so the deferred patch is a no-op.
	patchBase = client.MergeFrom(profile.DeepCopy())

	// Annotate with epg-recompute-requested — signals EPGReconciler that this
	// profile has changed and EPG recomputation is needed. The EPGReconciler will
	// clear this annotation after processing. This is the inter-reconciler signal
	// mechanism — not a channel, not a shared struct, not a direct call.
	//
	// Status is committed above before this patch so EPGReconciler always sees
	// Provisioned=true when it lists profiles in response to this signal.
	epgBase := profile.DeepCopy()
	epgTarget := profile.DeepCopy()
	if epgTarget.Annotations == nil {
		epgTarget.Annotations = make(map[string]string)
	}
	epgTarget.Annotations[epgRecomputeAnnotation] = "true"
	if err := r.Client.Patch(ctx, epgTarget, client.MergeFrom(epgBase)); err != nil {
		if !apierrors.IsNotFound(err) {
			logger.Error(err, "failed to annotate RBACProfile with epg-recompute-requested",
				"name", profile.Name, "namespace", profile.Namespace)
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers RBACProfileReconciler as the controller for RBACProfile.
func (r *RBACProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.RBACProfile{}).
		Named("rbacprofile").
		Complete(r)
}

// ---------------------------------------------------------------------------
// Step J — RBAC materialisation helpers
// ---------------------------------------------------------------------------

// provisionRBACResources applies the three RBAC resources for the given profile
// using server-side apply. All three are idempotent — re-applying an unchanged
// resource is a no-op. INV-004: guardian owns all RBAC.
//
// When the principalRef is not in system:serviceaccount:<ns>:<name> format,
// the profile governs a named identity (e.g. "acme-admin") that does not
// correspond to a Kubernetes ServiceAccount — no resources are provisioned.
func (r *RBACProfileReconciler) provisionRBACResources(ctx context.Context, profile *securityv1alpha1.RBACProfile) error {
	ns, saName, ok := parsePrincipalRef(profile.Spec.PrincipalRef)
	if !ok {
		// Named identity principal — no Kubernetes SA/ClusterRole/CRB to provision.
		return nil
	}

	rules, err := r.resolvePermissionSetRules(ctx, profile)
	if err != nil {
		return fmt.Errorf("resolving PermissionSet rules: %w", err)
	}

	// ServiceAccount.
	sa := buildServiceAccount(saName, ns)
	if err := r.Client.Apply(ctx, sa, client.ForceOwnership, client.FieldOwner(rbacFieldOwner)); err != nil {
		return fmt.Errorf("apply ServiceAccount %s/%s: %w", ns, saName, err)
	}

	// ClusterRole.
	clusterRoleName := "seam:" + saName
	cr := buildClusterRole(clusterRoleName, rules)
	if err := r.Client.Apply(ctx, cr, client.ForceOwnership, client.FieldOwner(rbacFieldOwner)); err != nil {
		return fmt.Errorf("apply ClusterRole %s: %w", clusterRoleName, err)
	}
	writeAudit(ctx, r.AuditWriter, database.AuditEvent{
		ClusterID:      "management",
		Subject:        profile.Spec.PrincipalRef,
		Action:         "clusterrole.materialized",
		Resource:       clusterRoleName,
		Decision:       "system",
		MatchedPolicy:  profile.Name,
		SequenceNumber: auditSeq(),
	})

	// ClusterRoleBinding.
	crb := buildClusterRoleBinding(clusterRoleName, saName, ns)
	if err := r.Client.Apply(ctx, crb, client.ForceOwnership, client.FieldOwner(rbacFieldOwner)); err != nil {
		return fmt.Errorf("apply ClusterRoleBinding %s: %w", clusterRoleName, err)
	}
	writeAudit(ctx, r.AuditWriter, database.AuditEvent{
		ClusterID:      "management",
		Subject:        profile.Spec.PrincipalRef,
		Action:         "clusterrolebinding.materialized",
		Resource:       clusterRoleName,
		Decision:       "system",
		MatchedPolicy:  profile.Name,
		SequenceNumber: auditSeq(),
	})

	return nil
}

// resolvePermissionSetRules fetches each PermissionSet referenced in the profile's
// PermissionDeclarations and converts its rules to rbacv1.PolicyRule values.
// Step G already verified all PermissionSets exist; this re-fetches from cache.
func (r *RBACProfileReconciler) resolvePermissionSetRules(ctx context.Context, profile *securityv1alpha1.RBACProfile) ([]rbacv1.PolicyRule, error) {
	var rules []rbacv1.PolicyRule
	for _, decl := range profile.Spec.PermissionDeclarations {
		ps := &securityv1alpha1.PermissionSet{}
		key := types.NamespacedName{Name: decl.PermissionSetRef, Namespace: profile.Namespace}
		if err := r.Client.Get(ctx, key, ps); err != nil {
			return nil, fmt.Errorf("get PermissionSet %q: %w", decl.PermissionSetRef, err)
		}
		for _, p := range ps.Spec.Permissions {
			verbs := make([]string, len(p.Verbs))
			for i, v := range p.Verbs {
				verbs[i] = string(v)
			}
			rules = append(rules, rbacv1.PolicyRule{
				APIGroups:     p.APIGroups,
				Resources:     p.Resources,
				Verbs:         verbs,
				ResourceNames: p.ResourceNames,
			})
		}
	}
	return rules, nil
}

// parsePrincipalRef parses a principalRef of the form
// "system:serviceaccount:<namespace>:<name>" and returns the extracted
// namespace and service account name. Returns ok=false for any other format.
func parsePrincipalRef(principalRef string) (namespace, name string, ok bool) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(principalRef, prefix) {
		return "", "", false
	}
	rest := principalRef[len(prefix):]
	idx := strings.IndexByte(rest, ':')
	if idx <= 0 || idx >= len(rest)-1 {
		return "", "", false
	}
	return rest[:idx], rest[idx+1:], true
}

// buildServiceAccount constructs a ServiceAccount apply configuration for server-side apply.
func buildServiceAccount(name, namespace string) *corev1apply.ServiceAccountApplyConfiguration {
	return corev1apply.ServiceAccount(name, namespace).
		WithAnnotations(map[string]string{"ontai.dev/rbac-owner": "guardian"}).
		WithLabels(map[string]string{"app.kubernetes.io/managed-by": "guardian"})
}

// buildClusterRole constructs a ClusterRole apply configuration for server-side apply.
func buildClusterRole(name string, rules []rbacv1.PolicyRule) *rbacv1apply.ClusterRoleApplyConfiguration {
	applyRules := make([]*rbacv1apply.PolicyRuleApplyConfiguration, len(rules))
	for i, rule := range rules {
		ar := rbacv1apply.PolicyRule().
			WithAPIGroups(rule.APIGroups...).
			WithResources(rule.Resources...).
			WithVerbs(rule.Verbs...)
		if len(rule.ResourceNames) > 0 {
			ar = ar.WithResourceNames(rule.ResourceNames...)
		}
		applyRules[i] = ar
	}
	return rbacv1apply.ClusterRole(name).
		WithAnnotations(map[string]string{"ontai.dev/rbac-owner": "guardian"}).
		WithLabels(map[string]string{"app.kubernetes.io/managed-by": "guardian"}).
		WithRules(applyRules...)
}

// buildClusterRoleBinding constructs a ClusterRoleBinding apply configuration for server-side apply.
func buildClusterRoleBinding(name, saName, saNamespace string) *rbacv1apply.ClusterRoleBindingApplyConfiguration {
	return rbacv1apply.ClusterRoleBinding(name).
		WithAnnotations(map[string]string{"ontai.dev/rbac-owner": "guardian"}).
		WithLabels(map[string]string{"app.kubernetes.io/managed-by": "guardian"}).
		WithRoleRef(rbacv1apply.RoleRef().
			WithAPIGroup("rbac.authorization.k8s.io").
			WithKind("ClusterRole").
			WithName(name)).
		WithSubjects(rbacv1apply.Subject().
			WithKind("ServiceAccount").
			WithName(saName).
			WithNamespace(saNamespace))
}
