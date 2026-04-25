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
// at bootstrap time. Guardian creates a baseline PermissionSet, RBACPolicy,
// and RBACProfile in the component's canonical namespace.
// guardian-schema.md §6, CS-INV-007.
type thirdPartyComponent struct {
	Name              string
	Namespace         string
	PrincipalRef      string
	ProfileName       string
	PolicyName        string
	PermissionSetName string
}

// managementThirdPartyComponents is the static list of third-party components
// Guardian wraps on the management cluster after the bootstrap annotation sweep.
// Cilium is excluded: kube-system is sweep-exempt and Cilium's cluster-scoped
// RBAC does not reside in a component-owned namespace.
var managementThirdPartyComponents = []thirdPartyComponent{
	{
		Name:              "cert-manager",
		Namespace:         "cert-manager",
		PrincipalRef:      "system:serviceaccount:cert-manager:cert-manager",
		ProfileName:       "rbac-cert-manager",
		PolicyName:        "cert-manager-rbac-policy",
		PermissionSetName: "cert-manager-baseline",
	},
	{
		Name:              "kueue",
		Namespace:         "kueue-system",
		PrincipalRef:      "system:serviceaccount:kueue-system:kueue-controller-manager",
		ProfileName:       "rbac-kueue",
		PolicyName:        "kueue-rbac-policy",
		PermissionSetName: "kueue-baseline",
	},
	{
		Name:              "cnpg",
		Namespace:         "security-system",
		PrincipalRef:      "system:serviceaccount:security-system:cloudnative-pg",
		ProfileName:       "rbac-cnpg",
		PolicyName:        "cnpg-rbac-policy",
		PermissionSetName: "cnpg-baseline",
	},
	{
		Name:              "metallb",
		Namespace:         "metallb-system",
		PrincipalRef:      "system:serviceaccount:metallb-system:controller",
		ProfileName:       "rbac-metallb",
		PolicyName:        "metallb-rbac-policy",
		PermissionSetName: "metallb-baseline",
	},
	{
		Name:              "local-path-provisioner",
		Namespace:         "local-path-storage",
		PrincipalRef:      "system:serviceaccount:local-path-storage:local-path-provisioner",
		ProfileName:       "rbac-local-path-provisioner",
		PolicyName:        "local-path-provisioner-rbac-policy",
		PermissionSetName: "local-path-provisioner-baseline",
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
// RBACProfile for each third-party component in its canonical namespace.
//
// Behaviour:
//   - Components whose namespace does not exist are skipped silently.
//   - Each resource is created only if absent (idempotent: runs safely on restart).
//   - Creation order within each component: PermissionSet first, RBACPolicy second,
//     RBACProfile last — the profile requires both to be present for reconciliation.
//
// Called by BootstrapAnnotationRunnable.Start after the annotation sweep completes,
// before SweepDone is set to true. guardian-schema.md §3 Step 2.
func (r *BootstrapAnnotationRunnable) createThirdPartyProfiles(ctx context.Context) error {
	log := ctrl.Log.WithName("bootstrap-third-party-profiles")

	for _, comp := range managementThirdPartyComponents {
		ns := &corev1.Namespace{}
		if err := r.Client.Get(ctx, client.ObjectKey{Name: comp.Namespace}, ns); err != nil {
			if apierrors.IsNotFound(err) {
				log.Info("skipping component: namespace not found",
					"component", comp.Name, "namespace", comp.Namespace)
				continue
			}
			return fmt.Errorf("third-party profiles: check namespace %q: %w", comp.Namespace, err)
		}

		if err := r.ensureComponentPermissionSet(ctx, comp); err != nil {
			return fmt.Errorf("third-party profiles: PermissionSet for %q: %w", comp.Name, err)
		}
		if err := r.ensureComponentRBACPolicy(ctx, comp); err != nil {
			return fmt.Errorf("third-party profiles: RBACPolicy for %q: %w", comp.Name, err)
		}
		if err := r.ensureComponentRBACProfile(ctx, comp); err != nil {
			return fmt.Errorf("third-party profiles: RBACProfile for %q: %w", comp.Name, err)
		}

		log.Info("third-party component wrapped", "component", comp.Name, "namespace", comp.Namespace)
	}
	return nil
}

func (r *BootstrapAnnotationRunnable) ensureComponentPermissionSet(ctx context.Context, comp thirdPartyComponent) error {
	existing := &securityv1alpha1.PermissionSet{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: comp.Namespace, Name: comp.PermissionSetName}, existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	ps := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: comp.Namespace,
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

func (r *BootstrapAnnotationRunnable) ensureComponentRBACPolicy(ctx context.Context, comp thirdPartyComponent) error {
	existing := &securityv1alpha1.RBACPolicy{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: comp.Namespace, Name: comp.PolicyName}, existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	policy := &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: comp.Namespace,
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

func (r *BootstrapAnnotationRunnable) ensureComponentRBACProfile(ctx context.Context, comp thirdPartyComponent) error {
	existing := &securityv1alpha1.RBACProfile{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: comp.Namespace, Name: comp.ProfileName}, existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	profile := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: comp.Namespace,
			Name:      comp.ProfileName,
			Labels: map[string]string{
				"ontai.dev/managed-by":        "guardian",
				"ontai.dev/rbac-profile-type": "third-party",
				"ontai.dev/component":         comp.Name,
			},
		},
		Spec: securityv1alpha1.RBACProfileSpec{
			PrincipalRef:   comp.PrincipalRef,
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
