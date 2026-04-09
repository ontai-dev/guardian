package controller

import (
	"context"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ontai-dev/guardian/internal/webhook"
)

const (
	// AnnotationRBACEnforcementMode is the annotation key stamped by the bootstrap
	// annotation sweep on pre-existing RBAC resources. It records the enforcement
	// tier at the time of annotation. guardian-schema.md §4, §6.
	AnnotationRBACEnforcementMode = "ontai.dev/rbac-enforcement-mode"

	// AnnotationRBACEnforcementModeAudit is the value stamped during the bootstrap
	// sweep. Resources annotated in audit mode are observed but not enforced against
	// until the namespace advances to full enforcement.
	AnnotationRBACEnforcementModeAudit = "audit"

	// bootstrapAnnotationFieldManager is the SSA field manager identifier for the
	// bootstrap annotation sweep. Using a distinct field manager separates sweep-owned
	// annotations from those managed by guardian's ongoing reconcilers.
	bootstrapAnnotationFieldManager = "guardian-bootstrap"
)

// BootstrapAnnotationRunnable scans all pre-existing RBAC resources on the cluster
// and stamps ownership annotations on any resource missing ontai.dev/rbac-owner=guardian.
//
// The sweep runs once on startup after the controller-runtime informer cache is ready
// (registered via mgr.Add). It completes before BootstrapController is permitted to
// advance WebhookMode from Initialising to ObserveOnly.
//
// Sweep behaviour:
//   - Namespaces carrying seam.ontai.dev/webhook-mode=exempt are skipped entirely.
//   - For all other namespaces: Roles, RoleBindings, and ServiceAccounts are scanned.
//   - ClusterRoles and ClusterRoleBindings are scanned once globally (cluster-scoped).
//   - Resources already carrying ontai.dev/rbac-owner=guardian are skipped.
//   - Resources missing the annotation are patched via SSA with:
//     ontai.dev/rbac-owner=guardian
//     ontai.dev/rbac-enforcement-mode=audit
//   - The patch uses fieldManager=guardian-bootstrap with ForceOwnership.
//   - The sweep is idempotent: running it twice produces the same result.
//
// On completion SweepDone is set to true, unblocking BootstrapController.
// guardian-schema.md §4. INV-020, CS-INV-004.
type BootstrapAnnotationRunnable struct {
	Client    client.Client
	SweepDone *atomic.Bool
}

// sweepSummary accumulates structured sweep metrics for the completion log.
type sweepSummary struct {
	namespacesScanned int
	namespacesSkipped int
	resourcesAnnotated int
	resourcesAlreadyOwned int
}

// Start implements the controller-runtime Runnable interface. Start is called by
// the manager exactly once, after the informer cache is ready. It performs the
// annotation sweep, logs a structured summary, and signals completion via SweepDone.
// A non-nil return from Start causes the manager to shut down.
func (r *BootstrapAnnotationRunnable) Start(ctx context.Context) error {
	log := ctrl.Log.WithName("bootstrap-annotation-sweep")
	log.Info("starting pre-existing RBAC annotation sweep")

	var summary sweepSummary

	// Enumerate all namespaces. Exempt namespaces are skipped.
	nsList := &corev1.NamespaceList{}
	if err := r.Client.List(ctx, nsList); err != nil {
		return err
	}

	for i := range nsList.Items {
		ns := &nsList.Items[i]
		if ns.Labels[webhook.WebhookModeLabelKey] == string(webhook.NamespaceModeExempt) {
			summary.namespacesSkipped++
			continue
		}
		summary.namespacesScanned++

		if err := r.sweepNamespacedResources(ctx, ns.Name, &summary); err != nil {
			return err
		}
	}

	// Sweep cluster-scoped RBAC resources once globally.
	if err := r.sweepClusterResources(ctx, &summary); err != nil {
		return err
	}

	log.Info("bootstrap annotation sweep complete",
		"namespacesScanned", summary.namespacesScanned,
		"namespacesSkipped", summary.namespacesSkipped,
		"resourcesAnnotated", summary.resourcesAnnotated,
		"resourcesAlreadyOwned", summary.resourcesAlreadyOwned,
	)

	r.SweepDone.Store(true)
	return nil
}

// sweepNamespacedResources annotates Roles, RoleBindings, and ServiceAccounts in ns.
func (r *BootstrapAnnotationRunnable) sweepNamespacedResources(ctx context.Context, ns string, sum *sweepSummary) error {
	// Roles
	roleList := &rbacv1.RoleList{}
	if err := r.Client.List(ctx, roleList, client.InNamespace(ns)); err != nil {
		return err
	}
	for i := range roleList.Items {
		item := &roleList.Items[i]
		if err := r.annotateRBACResource(ctx, item.Annotations, func() error {
			patch := &rbacv1.Role{
				TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      item.Name,
					Namespace: item.Namespace,
					Annotations: map[string]string{
						webhook.AnnotationRBACOwner:      webhook.AnnotationRBACOwnerValue,
						AnnotationRBACEnforcementMode:    AnnotationRBACEnforcementModeAudit,
					},
				},
			}
			return r.Client.Patch(ctx, patch, client.Apply, client.ForceOwnership, client.FieldOwner(bootstrapAnnotationFieldManager))
		}, sum); err != nil {
			return err
		}
	}

	// RoleBindings
	rbList := &rbacv1.RoleBindingList{}
	if err := r.Client.List(ctx, rbList, client.InNamespace(ns)); err != nil {
		return err
	}
	for i := range rbList.Items {
		item := &rbList.Items[i]
		if err := r.annotateRBACResource(ctx, item.Annotations, func() error {
			patch := &rbacv1.RoleBinding{
				TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      item.Name,
					Namespace: item.Namespace,
					Annotations: map[string]string{
						webhook.AnnotationRBACOwner:      webhook.AnnotationRBACOwnerValue,
						AnnotationRBACEnforcementMode:    AnnotationRBACEnforcementModeAudit,
					},
				},
			}
			return r.Client.Patch(ctx, patch, client.Apply, client.ForceOwnership, client.FieldOwner(bootstrapAnnotationFieldManager))
		}, sum); err != nil {
			return err
		}
	}

	// ServiceAccounts
	saList := &corev1.ServiceAccountList{}
	if err := r.Client.List(ctx, saList, client.InNamespace(ns)); err != nil {
		return err
	}
	for i := range saList.Items {
		item := &saList.Items[i]
		if err := r.annotateRBACResource(ctx, item.Annotations, func() error {
			patch := &corev1.ServiceAccount{
				TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      item.Name,
					Namespace: item.Namespace,
					Annotations: map[string]string{
						webhook.AnnotationRBACOwner:      webhook.AnnotationRBACOwnerValue,
						AnnotationRBACEnforcementMode:    AnnotationRBACEnforcementModeAudit,
					},
				},
			}
			return r.Client.Patch(ctx, patch, client.Apply, client.ForceOwnership, client.FieldOwner(bootstrapAnnotationFieldManager))
		}, sum); err != nil {
			return err
		}
	}

	return nil
}

// sweepClusterResources annotates ClusterRoles and ClusterRoleBindings.
// These are cluster-scoped and scanned once globally, not per-namespace.
func (r *BootstrapAnnotationRunnable) sweepClusterResources(ctx context.Context, sum *sweepSummary) error {
	// ClusterRoles
	crList := &rbacv1.ClusterRoleList{}
	if err := r.Client.List(ctx, crList); err != nil {
		return err
	}
	for i := range crList.Items {
		item := &crList.Items[i]
		if err := r.annotateRBACResource(ctx, item.Annotations, func() error {
			patch := &rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"},
				ObjectMeta: metav1.ObjectMeta{
					Name: item.Name,
					Annotations: map[string]string{
						webhook.AnnotationRBACOwner:      webhook.AnnotationRBACOwnerValue,
						AnnotationRBACEnforcementMode:    AnnotationRBACEnforcementModeAudit,
					},
				},
			}
			return r.Client.Patch(ctx, patch, client.Apply, client.ForceOwnership, client.FieldOwner(bootstrapAnnotationFieldManager))
		}, sum); err != nil {
			return err
		}
	}

	// ClusterRoleBindings
	crbList := &rbacv1.ClusterRoleBindingList{}
	if err := r.Client.List(ctx, crbList); err != nil {
		return err
	}
	for i := range crbList.Items {
		item := &crbList.Items[i]
		if err := r.annotateRBACResource(ctx, item.Annotations, func() error {
			patch := &rbacv1.ClusterRoleBinding{
				TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"},
				ObjectMeta: metav1.ObjectMeta{
					Name: item.Name,
					Annotations: map[string]string{
						webhook.AnnotationRBACOwner:      webhook.AnnotationRBACOwnerValue,
						AnnotationRBACEnforcementMode:    AnnotationRBACEnforcementModeAudit,
					},
				},
			}
			return r.Client.Patch(ctx, patch, client.Apply, client.ForceOwnership, client.FieldOwner(bootstrapAnnotationFieldManager))
		}, sum); err != nil {
			return err
		}
	}

	return nil
}

// annotateRBACResource checks whether the existing annotations already carry the
// ownership annotation, and if not, calls doPatch. Updates sum on each path.
// This helper centralises the already-owned / needs-patch decision.
func (r *BootstrapAnnotationRunnable) annotateRBACResource(
	_ context.Context,
	existing map[string]string,
	doPatch func() error,
	sum *sweepSummary,
) error {
	if existing[webhook.AnnotationRBACOwner] == webhook.AnnotationRBACOwnerValue {
		sum.resourcesAlreadyOwned++
		return nil
	}
	if err := doPatch(); err != nil {
		return err
	}
	sum.resourcesAnnotated++
	return nil
}
