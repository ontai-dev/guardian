package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/database"
)

// thirdPartyComponent describes a third-party component Guardian wraps at bootstrap
// time. The component namespace is discovered at runtime via ServiceAccountName --
// only the RBACProfile name and target SA are needed; no per-component policy or
// permission set is created under the three-layer RBAC hierarchy. guardian-schema.md §19.
type thirdPartyComponent struct {
	// Name is the human-readable component identifier used in log messages
	// and as the ontai.dev/component label value.
	Name string

	// ServiceAccountName is the well-known SA name the component creates in its
	// install namespace. Used to discover the actual namespace at runtime.
	ServiceAccountName string

	// NamespaceHint is the conventional install namespace. Used only as a
	// tiebreaker when ServiceAccountName matches in multiple non-system namespaces.
	NamespaceHint string

	// ProfileName is the RBACProfile CR name created in seam-tenant-{clusterName}.
	ProfileName string
}

// managementThirdPartyComponents is the catalog of third-party components Guardian
// wraps on the management cluster after the bootstrap annotation sweep. Namespaces
// are discovered at runtime via ServiceAccountName -- never hardcoded.
var managementThirdPartyComponents = []thirdPartyComponent{
	{
		Name:               "cert-manager",
		ServiceAccountName: "cert-manager",
		NamespaceHint:      "cert-manager",
		ProfileName:        "cert-manager",
	},
	{
		Name:               "kueue",
		ServiceAccountName: "kueue-controller-manager",
		ProfileName:        "kueue",
	},
	{
		Name:               "cnpg",
		ServiceAccountName: "cnpg-manager",
		ProfileName:        "cnpg",
	},
	{
		Name:               "metallb",
		ServiceAccountName: "metallb-controller",
		ProfileName:        "metallb",
	},
	{
		Name:               "local-path-provisioner",
		ServiceAccountName: "local-path-provisioner-service-account",
		ProfileName:        "local-path-provisioner",
	},
}

// createThirdPartyProfiles creates a component RBACProfile in seam-tenant-{clusterName}
// for each third-party component found on the cluster. Under the three-layer RBAC
// hierarchy (guardian-schema.md §19 Layer 3):
//   - No per-component PermissionSet is created (CS-INV-008).
//   - No per-component RBACPolicy is created (CS-INV-008).
//   - The RBACProfile references the cluster-scoped cluster-policy (Layer 2).
//   - All profiles land in seam-tenant-{clusterName}, not the component's namespace.
//
// Components whose SA cannot be found in any non-system namespace are skipped.
// Creation is idempotent: safe on manager restart.
// Called by BootstrapAnnotationRunnable.Start after the annotation sweep. §3 Step 2.
func (r *BootstrapAnnotationRunnable) createThirdPartyProfiles(ctx context.Context) error {
	log := ctrl.Log.WithName("bootstrap-third-party-profiles")
	tenantNS := "seam-tenant-" + r.ManagementClusterName

	for _, comp := range managementThirdPartyComponents {
		ns, principalRef, found := r.discoverComponentNamespace(ctx, comp)
		if !found {
			log.Info("skipping component: ServiceAccount not found in any non-system namespace",
				"component", comp.Name, "serviceAccount", comp.ServiceAccountName)
			continue
		}

		if err := r.ensureComponentRBACProfile(ctx, tenantNS, principalRef, comp); err != nil {
			return fmt.Errorf("third-party profiles: RBACProfile for %q: %w", comp.Name, err)
		}

		log.Info("third-party component wrapped",
			"component", comp.Name,
			"discoveredNamespace", ns,
			"profileNamespace", tenantNS,
		)
	}
	return nil
}

// discoverComponentNamespace finds the namespace where the component is installed
// by listing all ServiceAccounts across all non-system namespaces and matching by
// ServiceAccountName. Returns the namespace, principalRef, and whether found.
// NamespaceHint is used as a tiebreaker when multiple namespaces match.
func (r *BootstrapAnnotationRunnable) discoverComponentNamespace(
	ctx context.Context,
	comp thirdPartyComponent,
) (ns, principalRef string, found bool) {
	saList := &corev1.ServiceAccountList{}
	if err := r.Client.List(ctx, saList); err != nil {
		return "", "", false
	}

	var candidates []string
	for _, sa := range saList.Items {
		if sa.Name == comp.ServiceAccountName && !isThirdPartySystemNamespace(sa.Namespace) {
			candidates = append(candidates, sa.Namespace)
		}
	}

	switch len(candidates) {
	case 0:
		return "", "", false
	case 1:
		ns = candidates[0]
	default:
		ns = candidates[0]
		for _, c := range candidates {
			if c == comp.NamespaceHint {
				ns = c
				break
			}
		}
		ctrl.Log.WithName("bootstrap-third-party-profiles").Info(
			"multiple namespaces match SA name -- using preferred",
			"component", comp.Name, "serviceAccount", comp.ServiceAccountName,
			"matches", candidates, "selected", ns,
		)
	}

	principalRef = fmt.Sprintf("system:serviceaccount:%s:%s", ns, comp.ServiceAccountName)
	return ns, principalRef, true
}

// isThirdPartySystemNamespace returns true for namespaces excluded from SA discovery.
// Kubernetes system namespaces and Seam platform namespaces must not be treated as
// component install targets.
func isThirdPartySystemNamespace(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease",
		"ont-system", "seam-system":
		return true
	}
	return false
}

// ensureComponentRBACProfile creates the RBACProfile for a third-party component in
// the given tenant namespace if it does not already exist. The profile references
// cluster-policy and carries the component label. guardian-schema.md §19 Layer 3.
func (r *BootstrapAnnotationRunnable) ensureComponentRBACProfile(ctx context.Context, tenantNS, principalRef string, comp thirdPartyComponent) error {
	existing := &securityv1alpha1.RBACProfile{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: tenantNS, Name: comp.ProfileName}, existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	profile := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: tenantNS,
			Name:      comp.ProfileName,
			Labels: map[string]string{
				LabelKeyManagedBy:       LabelManagedByGuardian,
				LabelKeyPolicyType:      LabelValuePolicyTypeComponent,
				"ontai.dev/component":   comp.Name,
			},
		},
		Spec: securityv1alpha1.RBACProfileSpec{
			PrincipalRef:   principalRef,
			TargetClusters: []string{r.ManagementClusterName},
			RBACPolicyRef:  ClusterPolicyName,
			// Declares permissions via the shared cluster ceiling (§19 Layer 3).
			// No per-component PermissionSet exists; cluster-maximum is the sole ceiling.
			PermissionDeclarations: []securityv1alpha1.PermissionDeclaration{
				{
					PermissionSetRef: ClusterMaximumPermSetName,
					Scope:            securityv1alpha1.PermissionScopeCluster,
				},
			},
		},
	}
	if err := r.Client.Create(ctx, profile); err != nil {
		return err
	}
	writeAudit(ctx, r.AuditWriter, database.AuditEvent{
		ClusterID:      r.ManagementClusterName,
		Subject:        principalRef,
		Action:         "rbacprofile.component_wrapped",
		Resource:       comp.ProfileName,
		Decision:       "system",
		MatchedPolicy:  comp.Name,
		SequenceNumber: auditSeq(),
	})
	return nil
}
