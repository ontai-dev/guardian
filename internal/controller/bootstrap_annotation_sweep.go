package controller

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
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
)

// sweepAnnotationPatch is the JSON MergePatch applied to each un-owned RBAC resource
// during the bootstrap annotation sweep. It only touches metadata.annotations —
// no other field is present, so rules, subjects, roleRef, and all other fields
// are never modified or cleared. MergePatch is safe for annotation-only updates.
var sweepAnnotationPatch = mustBuildSweepAnnotationPatch()

func mustBuildSweepAnnotationPatch() []byte {
	type metaPatch struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	var p metaPatch
	p.Metadata.Annotations = map[string]string{
		webhook.AnnotationRBACOwner:   webhook.AnnotationRBACOwnerValue,
		AnnotationRBACEnforcementMode: AnnotationRBACEnforcementModeAudit,
	}
	b, err := json.Marshal(p)
	if err != nil {
		panic("guardian: failed to build sweep annotation patch: " + err.Error())
	}
	return b
}

// BootstrapAnnotationRunnable scans all pre-existing RBAC resources on the cluster
// and stamps ownership annotations on any resource missing ontai.dev/rbac-owner=guardian.
//
// The sweep runs once on startup after the controller-runtime informer cache is ready
// (registered via mgr.Add). It completes before BootstrapController is permitted to
// advance WebhookMode from Initialising to ObserveOnly.
//
// Sweep behaviour:
//   - Namespaces carrying seam.ontai.dev/webhook-mode=exempt are skipped entirely.
//   - kube-system is always skipped regardless of labels — system RBAC is never touched.
//   - ClusterRoles and ClusterRoleBindings whose name starts with "system:" are skipped —
//     these are Kubernetes built-in resources that must never be modified.
//   - For all other namespaces: Roles, RoleBindings, and ServiceAccounts are scanned.
//   - ClusterRoles and ClusterRoleBindings are scanned once globally (cluster-scoped).
//   - Resources already carrying ontai.dev/rbac-owner=guardian are skipped.
//   - Resources missing the annotation receive a metadata-only MergePatch:
//     ontai.dev/rbac-owner=guardian
//     ontai.dev/rbac-enforcement-mode=audit
//   - MergePatch only touches annotations — rules, subjects, roleRef are never modified.
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
	namespacesScanned      int
	namespacesSkipped      int
	resourcesAnnotated     int
	resourcesAlreadyOwned  int
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
// kube-system is always skipped regardless of labels.
func (r *BootstrapAnnotationRunnable) sweepNamespacedResources(ctx context.Context, ns string, sum *sweepSummary) error {
	// Never touch kube-system — Kubernetes system RBAC must not be modified.
	if ns == "kube-system" {
		return nil
	}

	// Roles
	roleList := &rbacv1.RoleList{}
	if err := r.Client.List(ctx, roleList, client.InNamespace(ns)); err != nil {
		return err
	}
	for i := range roleList.Items {
		item := &roleList.Items[i]
		if err := r.annotateRBACResource(ctx, item.Annotations, func() error {
			obj := &rbacv1.Role{}
			obj.Name = item.Name
			obj.Namespace = item.Namespace
			return r.Client.Patch(ctx, obj, client.RawPatch(apitypes.MergePatchType, sweepAnnotationPatch))
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
			obj := &rbacv1.RoleBinding{}
			obj.Name = item.Name
			obj.Namespace = item.Namespace
			return r.Client.Patch(ctx, obj, client.RawPatch(apitypes.MergePatchType, sweepAnnotationPatch))
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
			obj := &corev1.ServiceAccount{}
			obj.Name = item.Name
			obj.Namespace = item.Namespace
			return r.Client.Patch(ctx, obj, client.RawPatch(apitypes.MergePatchType, sweepAnnotationPatch))
		}, sum); err != nil {
			return err
		}
	}

	return nil
}

// sweepClusterResources annotates ClusterRoles and ClusterRoleBindings.
// These are cluster-scoped and scanned once globally, not per-namespace.
// Resources whose name starts with "system:" are always skipped.
func (r *BootstrapAnnotationRunnable) sweepClusterResources(ctx context.Context, sum *sweepSummary) error {
	// ClusterRoles
	crList := &rbacv1.ClusterRoleList{}
	if err := r.Client.List(ctx, crList); err != nil {
		return err
	}
	for i := range crList.Items {
		item := &crList.Items[i]
		// Never annotate system: ClusterRoles — Kubernetes built-in resources.
		// Patching them would risk clearing their rules field via SSA ownership.
		if strings.HasPrefix(item.Name, "system:") {
			continue
		}
		if err := r.annotateRBACResource(ctx, item.Annotations, func() error {
			obj := &rbacv1.ClusterRole{}
			obj.Name = item.Name
			return r.Client.Patch(ctx, obj, client.RawPatch(apitypes.MergePatchType, sweepAnnotationPatch))
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
		// Never annotate system: ClusterRoleBindings — Kubernetes built-in resources.
		if strings.HasPrefix(item.Name, "system:") {
			continue
		}
		if err := r.annotateRBACResource(ctx, item.Annotations, func() error {
			obj := &rbacv1.ClusterRoleBinding{}
			obj.Name = item.Name
			return r.Client.Patch(ctx, obj, client.RawPatch(apitypes.MergePatchType, sweepAnnotationPatch))
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
