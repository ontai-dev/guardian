package controller

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/database"
)

// tenantKnownComponents is the catalog of third-party components Guardian wraps
// on tenant clusters. Mirrors managementThirdPartyComponents but the RBACProfiles
// are placed in Namespace (ont-system) on the tenant cluster and reference the
// tenant's cluster-policy. guardian-schema.md §15 §19.
var tenantKnownComponents = []thirdPartyComponent{
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

// TenantProfileRunnable is a manager.Runnable that creates RBACProfiles in
// Namespace (ont-system) on the tenant cluster for each discovered third-party
// component. Under the three-layer RBAC hierarchy (guardian-schema.md §19):
//
//   - No per-component PermissionSet is created (CS-INV-008).
//   - No per-component RBACPolicy is created (CS-INV-008).
//   - Each RBACProfile references ClusterPolicyName ("cluster-policy").
//   - ClusterMaximumPermSetName ("cluster-maximum") is the sole permission ceiling.
//
// Runs periodically so newly deployed ClusterPacks are picked up automatically.
// Creation is idempotent.
type TenantProfileRunnable struct {
	// Client is the controller-runtime client scoped to the tenant cluster.
	Client client.Client

	// Namespace is the local operator namespace where profiles are written (ont-system).
	Namespace string

	// ClusterID is this tenant cluster's name, used in log messages.
	ClusterID string

	// Interval is the reconcile period.
	Interval time.Duration

	// AuditWriter receives rbacprofile.component_wrapped events for each newly created
	// profile. Nil and NoopAuditWriter are both safe -- tenant clusters carry no CNPG
	// dependency, so events are typically discarded. Wired for forward-compatibility.
	AuditWriter database.AuditWriter
}

// NeedLeaderElection satisfies manager.LeaderElectionRunnable.
func (r *TenantProfileRunnable) NeedLeaderElection() bool { return true }

// Start satisfies manager.Runnable. Runs until ctx is cancelled.
func (r *TenantProfileRunnable) Start(ctx context.Context) error {
	log := ctrl.Log.WithName("tenant-profile-runnable").WithValues("cluster", r.ClusterID)
	log.Info("started")
	r.runOnce(ctx)

	ticker := time.NewTicker(r.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.runOnce(ctx)
		}
	}
}

func (r *TenantProfileRunnable) runOnce(ctx context.Context) {
	log := ctrl.Log.WithName("tenant-profile-runnable").WithValues("cluster", r.ClusterID)
	for _, comp := range tenantKnownComponents {
		ns, principalRef, found := r.discoverComponentNamespace(ctx, comp)
		if !found {
			continue
		}
		if err := r.ensureRBACProfile(ctx, principalRef, comp); err != nil {
			log.Error(err, "ensure RBACProfile", "component", comp.Name)
			continue
		}
		log.V(1).Info("component wrapped", "component", comp.Name, "installNamespace", ns)
	}
}

func (r *TenantProfileRunnable) discoverComponentNamespace(ctx context.Context, comp thirdPartyComponent) (ns, principalRef string, found bool) {
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
	}
	principalRef = fmt.Sprintf("system:serviceaccount:%s:%s", ns, comp.ServiceAccountName)
	return ns, principalRef, true
}

func (r *TenantProfileRunnable) ensureRBACProfile(ctx context.Context, principalRef string, comp thirdPartyComponent) error {
	existing := &securityv1alpha1.RBACProfile{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: r.Namespace, Name: comp.ProfileName}, existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	profile := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.Namespace,
			Name:      comp.ProfileName,
			Labels: map[string]string{
				LabelKeyManagedBy:     LabelManagedByGuardian,
				LabelKeyPolicyType:    LabelValuePolicyTypeComponent,
				"ontai.dev/component": comp.Name,
			},
		},
		Spec: securityv1alpha1.RBACProfileSpec{
			PrincipalRef:   principalRef,
			TargetClusters: []string{r.ClusterID},
			// RBACPolicyRef is empty on tenant clusters. The governance ceiling
			// (cluster-policy/cluster-maximum) lives on the management cluster.
			// The PermissionSnapshot is the computed oracle for this cluster.
			// RBACProfileReconciler tenant path provisions without a local policy CR.
			// GUARDIAN-BL-RBACPROFILE-TENANT-PROVISIONING.
			RBACPolicyRef: "",
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
		ClusterID:      r.ClusterID,
		Subject:        principalRef,
		Action:         "rbacprofile.component_wrapped",
		Resource:       comp.ProfileName,
		Decision:       "system",
		MatchedPolicy:  comp.Name,
		SequenceNumber: auditSeq(),
	})
	return nil
}
