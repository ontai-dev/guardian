// Package controller -- ClusterRBACPolicyReconciler provisions the cluster-level
// RBACPolicy and PermissionSet for each InfrastructureTalosCluster and cascades
// deletion of all component RBACProfiles when the cluster is deleted.
// guardian-schema.md §18, §19, INV-004, CS-INV-008, CS-INV-009.
package controller

import (
	"context"
	"fmt"
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	seamv1alpha1 "github.com/ontai-dev/seam-core/api/v1alpha1"
)

const (
	// clusterRBACFinalizer is placed on InfrastructureTalosCluster to drive cascade
	// deletion of cluster-level RBAC objects when the cluster is removed.
	// Cross-namespace ownerReferences are prohibited; the finalizer is the authoritative
	// lifecycle coupling between TalosCluster (seam-system) and seam-tenant-* objects.
	// guardian-schema.md §18, CS-INV-008.
	clusterRBACFinalizer = "security.ontai.dev/cluster-rbac"

	// ClusterPolicyName is the canonical name of the cluster-level RBACPolicy
	// created in seam-tenant-{clusterName} for every InfrastructureTalosCluster.
	// guardian-schema.md §19 Layer 2.
	ClusterPolicyName = "cluster-policy"

	// ClusterMaximumPermSetName is the canonical name of the cluster-ceiling
	// PermissionSet that cluster-policy references as its maximum.
	// guardian-schema.md §19 Layer 2.
	ClusterMaximumPermSetName = "cluster-maximum"

	// ManagementPolicyName is the canonical name of the fleet-wide RBACPolicy
	// created by compiler enable in seam-system. guardian-schema.md §19 Layer 1.
	ManagementPolicyName = "management-policy"

	// ManagementMaximumPermSetName is the canonical name of the fleet-ceiling
	// PermissionSet in seam-system. guardian-schema.md §19 Layer 1.
	ManagementMaximumPermSetName = "management-maximum"

	// ManagementNamespace is the namespace where Layer 1 objects live.
	ManagementNamespace = "seam-system"

	// LabelKeyManagedBy is the label key used to identify guardian-managed objects.
	LabelKeyManagedBy = "ontai.dev/managed-by"

	// LabelManagedByGuardian is the value for LabelKeyManagedBy on guardian-owned objects.
	LabelManagedByGuardian = "guardian"

	// LabelKeyPolicyType distinguishes cluster-level objects from component objects.
	LabelKeyPolicyType = "ontai.dev/policy-type"

	// LabelValuePolicyTypeCluster identifies cluster-level PermissionSet / RBACPolicy.
	LabelValuePolicyTypeCluster = "cluster"

	// LabelValuePolicyTypeComponent identifies all non-seam-operator component RBACProfiles.
	// guardian-schema.md §19 Layer 3.
	LabelValuePolicyTypeComponent = "component"

	// LabelValuePolicyTypeSeamOperator identifies conductor-tenant and other seam-operator
	// profiles placed in seam-tenant-* namespaces by guardian. These are NOT swept by the
	// component backfill runnable and ARE deleted explicitly by reconcileDelete.
	// guardian-schema.md §20.
	LabelValuePolicyTypeSeamOperator = "seam-operator"

	// ConductorTenantProfileName is the name of the management-side RBACProfile guardian
	// creates in seam-tenant-{clusterName} for every role=tenant TalosCluster.
	// The tenant conductor pulls this profile and writes it into ont-system on the target
	// cluster. guardian-schema.md §20.
	ConductorTenantProfileName = "conductor-tenant"
)

// ClusterRBACPolicyReconciler watches InfrastructureTalosCluster CRs and maintains
// the cluster-level RBACPolicy (cluster-policy) and PermissionSet (cluster-maximum)
// in seam-tenant-{clusterName}. All non-seam-operator component RBACProfiles reference
// cluster-policy; there are no per-component RBACPolicy or PermissionSet objects.
// On TalosCluster deletion, all component-labeled RBACProfiles in the namespace are
// cascade-deleted before the cluster objects, then the finalizer is removed.
// guardian-schema.md §18, §19. Role=management only.
type ClusterRBACPolicyReconciler struct {
	Client client.Client
	Scheme *runtime.Scheme
}

// SetupWithManager registers two watch sources:
//  1. InfrastructureTalosCluster -- primary trigger for cluster RBAC provisioning.
//  2. management-maximum PermissionSet -- when its content changes, all TalosCluster
//     CRs are re-queued so cluster-maximum syncs to the updated fleet ceiling.
//     guardian-schema.md §18: "Re-validation occurs whenever management-maximum changes."
func (r *ClusterRBACPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&seamv1alpha1.InfrastructureTalosCluster{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Watches(
			&securityv1alpha1.PermissionSet{},
			handler.EnqueueRequestsFromMapFunc(r.EnqueueAllTalosClusters),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
				return obj.GetName() == ManagementMaximumPermSetName &&
					obj.GetNamespace() == ManagementNamespace
			})),
		).
		Complete(r)
}

// EnqueueAllTalosClusters returns reconcile requests for every InfrastructureTalosCluster
// in seam-system. Invoked when management-maximum changes so every cluster-maximum is
// validated and synced to the new fleet ceiling. Exported for unit testing. §18.
func (r *ClusterRBACPolicyReconciler) EnqueueAllTalosClusters(ctx context.Context, _ client.Object) []reconcile.Request {
	list := &seamv1alpha1.InfrastructureTalosClusterList{}
	if err := r.Client.List(ctx, list, client.InNamespace(ManagementNamespace)); err != nil {
		return nil
	}
	reqs := make([]reconcile.Request, len(list.Items))
	for i, tc := range list.Items {
		reqs[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{Name: tc.Name, Namespace: tc.Namespace},
		}
	}
	return reqs
}

// Reconcile implements the reconciliation loop for ClusterRBACPolicyReconciler.
func (r *ClusterRBACPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("taloscluster", req.NamespacedName)

	tc := &seamv1alpha1.InfrastructureTalosCluster{}
	if err := r.Client.Get(ctx, req.NamespacedName, tc); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get InfrastructureTalosCluster: %w", err)
	}

	if !tc.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, tc, logger)
	}

	return r.reconcileCreate(ctx, tc, logger)
}

// reconcileCreate ensures cluster-maximum PermissionSet and cluster-policy RBACPolicy
// exist in seam-tenant-{clusterName}, then adds the cluster-rbac finalizer.
// Validates cluster-maximum against management-maximum at creation time (CS-INV-009).
func (r *ClusterRBACPolicyReconciler) reconcileCreate(ctx context.Context, tc *seamv1alpha1.InfrastructureTalosCluster, logger interface {
	Info(string, ...interface{})
	Error(error, string, ...interface{})
}) (ctrl.Result, error) {
	ns := "seam-tenant-" + tc.Name

	// Step 1: read management-maximum to validate the cluster ceiling against it.
	// management-maximum is compiler-created and guaranteed present before guardian
	// starts. No deadlock risk. CS-INV-009, guardian-schema.md §19 Layer 2.
	mgmtMax := &securityv1alpha1.PermissionSet{}
	if err := r.Client.Get(ctx, types.NamespacedName{
		Name:      ManagementMaximumPermSetName,
		Namespace: ManagementNamespace,
	}, mgmtMax); err != nil {
		return ctrl.Result{}, fmt.Errorf("read management-maximum PermissionSet: %w", err)
	}

	clusterLabels := map[string]string{
		LabelKeyManagedBy:  LabelManagedByGuardian,
		LabelKeyPolicyType: LabelValuePolicyTypeCluster,
	}

	// Step 2: create or update cluster-maximum PermissionSet.
	// If it already exists with diverged permissions (management-maximum was updated),
	// sync it to the current fleet ceiling. This is the re-validation path triggered
	// by the management-maximum watch. guardian-schema.md §18, CS-INV-009.
	existingPS := &securityv1alpha1.PermissionSet{}
	if getErr := r.Client.Get(ctx, types.NamespacedName{Name: ClusterMaximumPermSetName, Namespace: ns}, existingPS); getErr != nil {
		if !apierrors.IsNotFound(getErr) {
			return ctrl.Result{}, fmt.Errorf("get cluster-maximum PermissionSet in %s: %w", ns, getErr)
		}
		ps := &securityv1alpha1.PermissionSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ClusterMaximumPermSetName,
				Namespace: ns,
				Labels:    clusterLabels,
			},
			Spec: securityv1alpha1.PermissionSetSpec{
				Description: "Cluster permission ceiling for " + tc.Name,
				Permissions: mgmtMax.Spec.Permissions,
			},
		}
		if err := r.Client.Create(ctx, ps); err != nil && !apierrors.IsAlreadyExists(err) {
			return ctrl.Result{}, fmt.Errorf("create cluster-maximum PermissionSet in %s: %w", ns, err)
		}
	} else if !reflect.DeepEqual(existingPS.Spec.Permissions, mgmtMax.Spec.Permissions) {
		updated := existingPS.DeepCopy()
		updated.Spec.Permissions = mgmtMax.Spec.Permissions
		if err := r.Client.Update(ctx, updated); err != nil {
			return ctrl.Result{}, fmt.Errorf("update cluster-maximum PermissionSet in %s: %w", ns, err)
		}
		logger.Info("synced cluster-maximum to management-maximum", "cluster", tc.Name, "namespace", ns)
	}

	// Step 3: create cluster-policy RBACPolicy if absent.
	policy := &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ClusterPolicyName,
			Namespace: ns,
			Labels:    clusterLabels,
		},
		Spec: securityv1alpha1.RBACPolicySpec{
			SubjectScope:            "tenant",
			EnforcementMode:         "audit",
			AllowedClusters:         []string{tc.Name},
			MaximumPermissionSetRef: ClusterMaximumPermSetName,
		},
	}
	if err := r.Client.Create(ctx, policy); err != nil && !apierrors.IsAlreadyExists(err) {
		return ctrl.Result{}, fmt.Errorf("create cluster-policy RBACPolicy in %s: %w", ns, err)
	}

	// Step 3.5: for role=tenant clusters, provision the conductor-tenant RBACProfile in
	// seam-tenant-{clusterName}. This is the management-side authoritative profile that
	// the tenant conductor pulls and writes into ont-system on the target cluster.
	// guardian-schema.md §20.
	if tc.Spec.Role == seamv1alpha1.InfrastructureTalosClusterRoleTenant {
		if err := r.ensureConductorTenantProfile(ctx, tc, ns); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Step 4: add finalizer so deletion cascade runs.
	if !controllerutil.ContainsFinalizer(tc, clusterRBACFinalizer) {
		controllerutil.AddFinalizer(tc, clusterRBACFinalizer)
		if err := r.Client.Update(ctx, tc); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer to TalosCluster %s: %w", tc.Name, err)
		}
		logger.Info("provisioned cluster RBAC objects", "cluster", tc.Name, "namespace", ns)
	}

	return ctrl.Result{}, nil
}

// ensureConductorTenantProfile creates the management-side conductor-tenant RBACProfile
// in seam-tenant-{clusterName} for role=tenant TalosCluster objects. The profile is
// authoritative on the management cluster; the tenant conductor pulls it from there and
// writes it into ont-system on the target cluster. Idempotent. guardian-schema.md §20.
func (r *ClusterRBACPolicyReconciler) ensureConductorTenantProfile(
	ctx context.Context,
	tc *seamv1alpha1.InfrastructureTalosCluster,
	ns string,
) error {
	profile := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ConductorTenantProfileName,
			Namespace: ns,
			Labels: map[string]string{
				LabelKeyManagedBy:  LabelManagedByGuardian,
				LabelKeyPolicyType: LabelValuePolicyTypeSeamOperator,
			},
		},
		Spec: securityv1alpha1.RBACProfileSpec{
			PrincipalRef:   "conductor",
			TargetClusters: []string{tc.Name},
			RBACPolicyRef:  ClusterPolicyName,
			PermissionDeclarations: []securityv1alpha1.PermissionDeclaration{
				{
					PermissionSetRef: ClusterMaximumPermSetName,
					Scope:            securityv1alpha1.PermissionScopeCluster,
				},
			},
		},
	}
	if err := r.Client.Create(ctx, profile); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create conductor-tenant RBACProfile in %s: %w", ns, err)
	}
	return nil
}

// reconcileDelete cascades deletion of all component RBACProfiles, then cluster objects,
// then removes the finalizer from the TalosCluster.
func (r *ClusterRBACPolicyReconciler) reconcileDelete(ctx context.Context, tc *seamv1alpha1.InfrastructureTalosCluster, logger interface {
	Info(string, ...interface{})
	Error(error, string, ...interface{})
}) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(tc, clusterRBACFinalizer) {
		return ctrl.Result{}, nil
	}

	ns := "seam-tenant-" + tc.Name
	componentSelector := client.MatchingLabels{LabelKeyPolicyType: LabelValuePolicyTypeComponent}

	// Step 1a: for role=tenant clusters, delete conductor-tenant seam-operator profile.
	// This profile is NOT labeled component, so the component sweep below will not reach it.
	// guardian-schema.md §20.
	if tc.Spec.Role == seamv1alpha1.InfrastructureTalosClusterRoleTenant {
		conductorProfile := &securityv1alpha1.RBACProfile{
			ObjectMeta: metav1.ObjectMeta{Name: ConductorTenantProfileName, Namespace: ns},
		}
		if err := r.Client.Delete(ctx, conductorProfile); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("delete conductor-tenant RBACProfile in %s: %w", ns, err)
		}
	}

	// Step 1: delete all component RBACProfiles in the namespace.
	// These are all non-seam-operator profiles (third-party, pack components).
	// guardian-schema.md §19 Layer 3, §18 deletion cascade.
	profileList := &securityv1alpha1.RBACProfileList{}
	if err := r.Client.List(ctx, profileList, client.InNamespace(ns), componentSelector); err != nil {
		return ctrl.Result{}, fmt.Errorf("list component RBACProfiles in %s: %w", ns, err)
	}
	for i := range profileList.Items {
		if err := r.Client.Delete(ctx, &profileList.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("delete RBACProfile %s/%s: %w", ns, profileList.Items[i].Name, err)
		}
	}
	logger.Info("deleted component RBACProfiles", "namespace", ns, "count", len(profileList.Items))

	// Step 2: delete cluster-maximum PermissionSet.
	clusterPS := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{Name: ClusterMaximumPermSetName, Namespace: ns},
	}
	if err := r.Client.Delete(ctx, clusterPS); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("delete cluster-maximum PermissionSet in %s: %w", ns, err)
	}

	// Step 3: delete cluster-policy RBACPolicy.
	clusterPolicy := &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: ClusterPolicyName, Namespace: ns},
	}
	if err := r.Client.Delete(ctx, clusterPolicy); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("delete cluster-policy RBACPolicy in %s: %w", ns, err)
	}

	logger.Info("deleted cluster-level RBAC objects", "namespace", ns)

	// Step 4: remove finalizer to let TalosCluster complete deletion.
	controllerutil.RemoveFinalizer(tc, clusterRBACFinalizer)
	if err := r.Client.Update(ctx, tc); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove cluster-rbac finalizer from TalosCluster %s: %w", tc.Name, err)
	}

	return ctrl.Result{}, nil
}
