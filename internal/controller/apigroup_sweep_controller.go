package controller

import (
	"context"
	"fmt"
	"sort"
	"strings"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

const (
	// managementMaximumName is the Layer 1 fleet ceiling PermissionSet.
	managementMaximumName      = "management-maximum"
	managementMaximumNamespace = "seam-system"

	// guardianSingletonName is the canonical Guardian CR name.
	guardianSingletonName = "guardian"

	// sweepSingletonKey is the synthetic reconcile key used by the sweep.
	sweepSingletonKey = "sweep/apigroups"
)

// allStandardVerbs are the verbs added for every auto-discovered API group rule.
var allStandardVerbs = []securityv1alpha1.Verb{
	securityv1alpha1.VerbGet,
	securityv1alpha1.VerbList,
	securityv1alpha1.VerbWatch,
	securityv1alpha1.VerbCreate,
	securityv1alpha1.VerbUpdate,
	securityv1alpha1.VerbPatch,
	securityv1alpha1.VerbDelete,
}

// APIGroupSweepController watches CustomResourceDefinitions and extends
// management-maximum with explicit PermissionRule entries for every
// third-party API group discovered. guardian-schema.md §21.
//
// Runs on role=management only.
//
// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=list;watch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=permissionsets,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=guardians,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=guardians/status,verbs=get;update;patch
type APIGroupSweepController struct {
	// Client is the controller-runtime client.
	Client client.Client

	// Scheme is the runtime scheme.
	Scheme *runtime.Scheme

	// OperatorNamespace is the namespace where management-maximum and the Guardian
	// singleton CR live (seam-system).
	OperatorNamespace string
}

// Reconcile reconciles a synthetic singleton key. On every CRD change event it
// lists all CRDs, extracts third-party API groups, and patches management-maximum
// with any new explicit PermissionRule entries.
func (r *APIGroupSweepController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	if req.Name != sweepSingletonKey {
		return ctrl.Result{}, nil
	}

	// Fetch management-maximum. If absent, requeue -- it should be created by
	// compiler enable before any sweep can meaningfully run.
	ps := &securityv1alpha1.PermissionSet{}
	psKey := types.NamespacedName{Name: managementMaximumName, Namespace: r.OperatorNamespace}
	if err := r.Client.Get(ctx, psKey, ps); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("management-maximum not yet present; will retry", "namespace", r.OperatorNamespace)
			return ctrl.Result{RequeueAfter: 30e9}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get management-maximum: %w", err)
	}

	// List all CRDs on this cluster.
	crdList := &apiextensionsv1.CustomResourceDefinitionList{}
	if err := r.Client.List(ctx, crdList); err != nil {
		return ctrl.Result{}, fmt.Errorf("list CRDs: %w", err)
	}

	// Collect the set of third-party API groups present in the cluster.
	thirdParty := CollectThirdPartyGroups(crdList.Items)

	// Compute which groups are not yet represented by an explicit rule in
	// management-maximum (check APIGroups slice for exact match only).
	existingExplicit := ExplicitGroupsInPermissionSet(ps)
	var newGroups []string
	for g := range thirdParty {
		if !existingExplicit[g] {
			newGroups = append(newGroups, g)
		}
	}
	sort.Strings(newGroups)

	if len(newGroups) > 0 {
		patch := client.MergeFrom(ps.DeepCopy())
		for _, g := range newGroups {
			ps.Spec.Permissions = append(ps.Spec.Permissions, securityv1alpha1.PermissionRule{
				APIGroups: []string{g},
				Resources: []string{"*"},
				Verbs:     allStandardVerbs,
			})
		}
		if err := r.Client.Patch(ctx, ps, patch); err != nil {
			return ctrl.Result{}, fmt.Errorf("patch management-maximum: %w", err)
		}
		logger.Info("management-maximum extended with new API groups",
			"added", newGroups, "total", len(ps.Spec.Permissions))
	}

	// Build sorted deduplicated discovered set (union of existing + new).
	for g := range thirdParty {
		existingExplicit[g] = true
	}
	discovered := sortedKeys(existingExplicit)

	// Update Guardian singleton status with the discovered groups.
	if err := r.updateDiscoveredGroups(ctx, discovered); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers the APIGroupSweepController and maps all CRD events
// to the singleton sweep key. guardian-schema.md §21.
func (r *APIGroupSweepController) SetupWithManager(mgr ctrl.Manager) error {
	if err := apiextensionsv1.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("APIGroupSweepController: register apiextensions scheme: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.PermissionSet{}).
		Watches(
			&apiextensionsv1.CustomResourceDefinition{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, _ client.Object) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: sweepSingletonKey}}}
			}),
		).
		Named("apigroup-sweep").
		Complete(r)
}

// updateDiscoveredGroups writes the sorted discovered group list into Guardian status.
func (r *APIGroupSweepController) updateDiscoveredGroups(ctx context.Context, groups []string) error {
	gdn := &securityv1alpha1.Guardian{}
	gdnKey := types.NamespacedName{Name: guardianSingletonName, Namespace: r.OperatorNamespace}
	if err := r.Client.Get(ctx, gdnKey, gdn); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get Guardian singleton: %w", err)
	}
	if stringSliceEqual(gdn.Status.DiscoveredAPIGroups, groups) {
		return nil
	}
	patch := client.MergeFrom(gdn.DeepCopy())
	gdn.Status.DiscoveredAPIGroups = groups
	if err := r.Client.Status().Patch(ctx, gdn, patch); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("patch Guardian status: %w", err)
	}
	return nil
}

// CollectThirdPartyGroups returns a set of API groups extracted from the CRD list
// after filtering out system-owned and seam-owned groups. guardian-schema.md §21.
// Exported for unit testing.
func CollectThirdPartyGroups(crds []apiextensionsv1.CustomResourceDefinition) map[string]bool {
	out := make(map[string]bool)
	for _, crd := range crds {
		g := crd.Spec.Group
		if !IsSystemGroup(g) {
			out[g] = true
		}
	}
	return out
}

// IsSystemGroup returns true for groups that should never receive auto-generated rules.
// guardian-schema.md §21 Exclusion list. Exported for unit testing.
func IsSystemGroup(group string) bool {
	if group == "" {
		return true
	}
	// k8s built-in bare groups.
	switch group {
	case "apps", "batch", "autoscaling", "policy", "core":
		return true
	}
	// All k8s extension and CAPI ecosystem groups.
	if strings.HasSuffix(group, ".k8s.io") {
		return true
	}
	if strings.HasSuffix(group, ".x-k8s.io") {
		return true
	}
	// Seam-owned groups.
	if strings.HasSuffix(group, ".ontai.dev") {
		return true
	}
	return false
}

// ExplicitGroupsInPermissionSet returns a set of API groups that already have at
// least one explicit (non-wildcard) rule in the PermissionSet. Wildcard ("*") rules
// are excluded from this set -- the sweep adds explicit per-group rules regardless
// of an existing wildcard. Exported for unit testing.
func ExplicitGroupsInPermissionSet(ps *securityv1alpha1.PermissionSet) map[string]bool {
	out := make(map[string]bool)
	for _, rule := range ps.Spec.Permissions {
		for _, g := range rule.APIGroups {
			if g != "*" && g != "" {
				out[g] = true
			}
		}
	}
	return out
}

// sortedKeys returns a sorted slice of the map keys.
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// stringSliceEqual returns true if a and b have equal length and identical elements.
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ensureManagementMaximum creates management-maximum if it does not exist.
// Called during startup reconcile to ensure the PermissionSet exists before CRD
// sweep runs. No-op if already present.
func ensureManagementMaximum(ctx context.Context, c client.Client, namespace string) error {
	ps := &securityv1alpha1.PermissionSet{}
	key := types.NamespacedName{Name: managementMaximumName, Namespace: namespace}
	err := c.Get(ctx, key, ps)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("check management-maximum: %w", err)
	}
	newPS := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      managementMaximumName,
			Namespace: namespace,
		},
		Spec: securityv1alpha1.PermissionSetSpec{
			Description: "Layer 1 fleet ceiling. guardian-schema.md §19.",
			Permissions: []securityv1alpha1.PermissionRule{
				{
					APIGroups: []string{"*"},
					Resources: []string{"*"},
					Verbs:     allStandardVerbs,
				},
			},
		},
	}
	if err := c.Create(ctx, newPS); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create management-maximum: %w", err)
	}
	return nil
}
