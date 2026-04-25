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
)

// thirdPartyComponent describes a third-party component that Guardian wraps
// at bootstrap time. The component namespace is NOT hardcoded — it is
// discovered at runtime by finding the ServiceAccountName across all
// non-system namespaces. This handles arbitrary install namespaces.
// guardian-schema.md §6, CS-INV-007.
type thirdPartyComponent struct {
	// Name is the human-readable component identifier used in log messages
	// and as the ontai.dev/component label value.
	Name string

	// ServiceAccountName is the well-known SA name that the component creates
	// in its install namespace. Used to discover the actual namespace at runtime.
	// Must be unique enough to avoid false matches; see NamespaceHint for
	// disambiguation when multiple namespaces carry the same SA name.
	ServiceAccountName string

	// NamespaceHint is the conventional install namespace for this component.
	// Used only as a tiebreaker when ServiceAccountName matches SAs in multiple
	// non-system namespaces. Empty means: accept the first match found.
	NamespaceHint string

	// ProfileName, PolicyName, PermissionSetName are the CR names created in
	// the discovered namespace.
	ProfileName       string
	PolicyName        string
	PermissionSetName string
}

// managementThirdPartyComponents is the catalog of third-party components
// Guardian wraps on the management cluster after the bootstrap annotation sweep.
// Namespaces are discovered at runtime via ServiceAccountName — never hardcoded.
var managementThirdPartyComponents = []thirdPartyComponent{
	{
		Name:               "cert-manager",
		ServiceAccountName: "cert-manager",
		NamespaceHint:      "cert-manager",
		ProfileName:        "rbac-cert-manager",
		PolicyName:         "cert-manager-rbac-policy",
		PermissionSetName:  "cert-manager-baseline",
	},
	{
		Name:               "kueue",
		ServiceAccountName: "kueue-controller-manager",
		ProfileName:        "rbac-kueue",
		PolicyName:         "kueue-rbac-policy",
		PermissionSetName:  "kueue-baseline",
	},
	{
		Name:               "cnpg",
		ServiceAccountName: "cnpg-manager",
		ProfileName:        "rbac-cnpg",
		PolicyName:         "cnpg-rbac-policy",
		PermissionSetName:  "cnpg-baseline",
	},
	{
		Name:               "metallb",
		ServiceAccountName: "metallb-controller",
		ProfileName:        "rbac-metallb",
		PolicyName:         "metallb-rbac-policy",
		PermissionSetName:  "metallb-baseline",
	},
	{
		Name:               "local-path-provisioner",
		ServiceAccountName: "local-path-provisioner-service-account",
		ProfileName:        "rbac-local-path-provisioner",
		PolicyName:         "local-path-provisioner-rbac-policy",
		PermissionSetName:  "local-path-provisioner-baseline",
	},
}

// baselinePermissions is the broad bootstrap grant used for all third-party
// component PermissionSets. Permits all standard RBAC verbs on all resources.
// These are bootstrap-phase grants — operators may tighten to least-privilege
// post-bootstrap. guardian-schema.md §6.
var baselinePermissions = []securityv1alpha1.PermissionRule{
	{
		APIGroups: []string{"*"},
		Resources: []string{"*"},
		Verbs: []securityv1alpha1.Verb{
			securityv1alpha1.VerbGet,
			securityv1alpha1.VerbList,
			securityv1alpha1.VerbWatch,
			securityv1alpha1.VerbCreate,
			securityv1alpha1.VerbUpdate,
			securityv1alpha1.VerbPatch,
			securityv1alpha1.VerbDelete,
		},
	},
}

// createThirdPartyProfiles creates baseline PermissionSet, RBACPolicy, and
// RBACProfile for each third-party component in its discovered namespace.
//
// Behaviour:
//   - Component namespace is discovered by finding ServiceAccountName across
//     all non-system namespaces — no namespace is hardcoded in the catalog.
//   - Components whose SA cannot be found are skipped silently.
//   - Each resource is created only if absent (idempotent: runs safely on restart).
//   - Creation order within each component: PermissionSet first, RBACPolicy second,
//     RBACProfile last — the profile requires both for reconciliation.
//
// Called by BootstrapAnnotationRunnable.Start after the annotation sweep completes,
// before SweepDone is set to true. guardian-schema.md §3 Step 2.
func (r *BootstrapAnnotationRunnable) createThirdPartyProfiles(ctx context.Context) error {
	log := ctrl.Log.WithName("bootstrap-third-party-profiles")

	for _, comp := range managementThirdPartyComponents {
		ns, principalRef, found := r.discoverComponentNamespace(ctx, comp)
		if !found {
			log.Info("skipping component: ServiceAccount not found in any non-system namespace",
				"component", comp.Name, "serviceAccount", comp.ServiceAccountName)
			continue
		}

		if err := r.ensureComponentPermissionSet(ctx, ns, comp); err != nil {
			return fmt.Errorf("third-party profiles: PermissionSet for %q: %w", comp.Name, err)
		}
		if err := r.ensureComponentRBACPolicy(ctx, ns, comp); err != nil {
			return fmt.Errorf("third-party profiles: RBACPolicy for %q: %w", comp.Name, err)
		}
		if err := r.ensureComponentRBACProfile(ctx, ns, principalRef, comp); err != nil {
			return fmt.Errorf("third-party profiles: RBACProfile for %q: %w", comp.Name, err)
		}

		log.Info("third-party component wrapped", "component", comp.Name, "namespace", ns)
	}
	return nil
}

// discoverComponentNamespace finds the namespace where the component is installed
// by listing all ServiceAccounts across all non-system namespaces and matching
// by the component's ServiceAccountName. Returns the namespace, principalRef,
// and whether the component was found.
//
// When multiple non-system namespaces contain an SA with the same name, the
// NamespaceHint is used to prefer the conventional install namespace.
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
		// Multiple matches: prefer the hint namespace if present.
		ns = candidates[0]
		for _, c := range candidates {
			if c == comp.NamespaceHint {
				ns = c
				break
			}
		}
		ctrl.Log.WithName("bootstrap-third-party-profiles").Info(
			"multiple namespaces match SA name — using preferred",
			"component", comp.Name, "serviceAccount", comp.ServiceAccountName,
			"matches", candidates, "selected", ns,
		)
	}

	principalRef = fmt.Sprintf("system:serviceaccount:%s:%s", ns, comp.ServiceAccountName)
	return ns, principalRef, true
}

// isThirdPartySystemNamespace returns true for namespaces that must be excluded
// from the third-party component discovery scan. Kubernetes system namespaces
// and Seam platform namespaces must not be treated as component install targets.
func isThirdPartySystemNamespace(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease",
		"ont-system", "seam-system":
		return true
	}
	return false
}

func (r *BootstrapAnnotationRunnable) ensureComponentPermissionSet(ctx context.Context, ns string, comp thirdPartyComponent) error {
	existing := &securityv1alpha1.PermissionSet{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: comp.PermissionSetName}, existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	ps := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      comp.PermissionSetName,
			Labels: map[string]string{
				"ontai.dev/managed-by":          "guardian",
				"ontai.dev/permission-set-type": "bootstrap",
				"ontai.dev/component":           comp.Name,
			},
		},
		Spec: securityv1alpha1.PermissionSetSpec{
			Description: comp.Name + " bootstrap baseline permissions",
			Permissions: baselinePermissions,
		},
	}
	return r.Client.Create(ctx, ps)
}

func (r *BootstrapAnnotationRunnable) ensureComponentRBACPolicy(ctx context.Context, ns string, comp thirdPartyComponent) error {
	existing := &securityv1alpha1.RBACPolicy{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: comp.PolicyName}, existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	policy := &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      comp.PolicyName,
			Labels: map[string]string{
				"ontai.dev/managed-by": "guardian",
				"ontai.dev/component":  comp.Name,
			},
		},
		Spec: securityv1alpha1.RBACPolicySpec{
			SubjectScope:            securityv1alpha1.SubjectScopePlatform,
			MaximumPermissionSetRef: comp.PermissionSetName,
			EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
		},
	}
	return r.Client.Create(ctx, policy)
}

func (r *BootstrapAnnotationRunnable) ensureComponentRBACProfile(ctx context.Context, ns, principalRef string, comp thirdPartyComponent) error {
	existing := &securityv1alpha1.RBACProfile{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: comp.ProfileName}, existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	profile := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      comp.ProfileName,
			Labels: map[string]string{
				"ontai.dev/managed-by":        "guardian",
				"ontai.dev/rbac-profile-type": "third-party",
				"ontai.dev/component":         comp.Name,
			},
		},
		Spec: securityv1alpha1.RBACProfileSpec{
			PrincipalRef:   principalRef,
			TargetClusters: []string{"management"},
			PermissionDeclarations: []securityv1alpha1.PermissionDeclaration{
				{
					PermissionSetRef: comp.PermissionSetName,
					Scope:            securityv1alpha1.PermissionScopeCluster,
				},
			},
			RBACPolicyRef: comp.PolicyName,
		},
	}
	return r.Client.Create(ctx, profile)
}
