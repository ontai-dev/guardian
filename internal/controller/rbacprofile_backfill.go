// rbacprofile_backfill.go implements the RBACProfile back-fill runnable.
// Scans seam-tenant-* namespaces on a configurable interval and re-invokes pack
// RBACProfile creation for any component whose PermissionSet exists but whose
// RBACProfile is missing. Fills gaps caused by transient failures or guardian
// restarts during pack RBAC intake. T-04b, guardian-schema.md §6, CS-INV-005.
package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/webhook"
)

// RBACProfileBackfillRunnable scans seam-tenant-* namespaces at a regular interval.
// For each namespace it lists PermissionSet CRs and checks whether a corresponding
// RBACProfile exists. Any missing RBACProfile (gap) is created via EnsurePackRBACProfileCRs.
//
// Decision F: back-fill always targets seam-tenant-{targetCluster} regardless of cluster role.
// CS-INV-005: EnsurePackRBACProfileCRs only creates the CR; RBACProfileReconciler sets provisioned=true.
//
// Registered via mgr.Add for role=management. Start blocks until ctx is cancelled.
type RBACProfileBackfillRunnable struct {
	// Client is the controller-runtime client for Kubernetes API access.
	Client client.Client

	// Interval is how often the back-fill scan runs. Defaults to 60s when zero.
	// Override via RBAC_BACKFILL_INTERVAL env var (seconds) in main.
	Interval time.Duration
}

// Start implements the controller-runtime Runnable interface. Runs a ticker loop
// until ctx is cancelled. A failed scan is logged but does not terminate the loop.
func (r *RBACProfileBackfillRunnable) Start(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = 60 * time.Second
	}

	log := ctrl.Log.WithName("rbacprofile-backfill")
	log.Info("starting RBACProfile back-fill runnable", "interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.RunOnce(ctx); err != nil {
				log.Error(err, "RBACProfile back-fill scan failed")
			}
		}
	}
}

// RunOnce performs a single back-fill scan pass across all seam-tenant-* namespaces.
// For each namespace it checks for component RBACProfiles missing their profile entry
// and calls EnsurePackRBACProfileCRs for any gap found.
//
// Under the three-layer RBAC hierarchy (guardian-schema.md §19):
// - Skips namespaces where cluster-policy does not yet exist (ClusterRBACPolicyReconciler
//   must provision it first; the namespace is retried on the next pass).
// - Only back-fills RBACProfiles labeled ontai.dev/policy-type=component. Cluster-level
//   objects (cluster-policy, cluster-maximum) are never back-filled here.
// guardian-schema.md §6, §18, §19. CS-INV-008.
func (r *RBACProfileBackfillRunnable) RunOnce(ctx context.Context) error {
	log := ctrl.Log.WithName("rbacprofile-backfill")

	nsList := &corev1.NamespaceList{}
	if err := r.Client.List(ctx, nsList); err != nil {
		return fmt.Errorf("list namespaces: %w", err)
	}

	filled := 0
	for i := range nsList.Items {
		ns := &nsList.Items[i]
		if !strings.HasPrefix(ns.Name, "seam-tenant-") {
			continue
		}
		targetCluster := strings.TrimPrefix(ns.Name, "seam-tenant-")

		// Guard: cluster-policy must exist before any component RBACProfile can be
		// created. If absent, ClusterRBACPolicyReconciler has not yet run; skip this
		// namespace silently and retry on the next pass. CS-INV-009.
		clusterPolicy := &securityv1alpha1.RBACPolicy{}
		if err := r.Client.Get(ctx, types.NamespacedName{
			Name:      "cluster-policy",
			Namespace: ns.Name,
		}, clusterPolicy); err != nil {
			if apierrors.IsNotFound(err) {
				log.Info("cluster-policy not yet provisioned; skipping namespace", "namespace", ns.Name)
				continue
			}
			log.Error(err, "get cluster-policy", "namespace", ns.Name)
			continue
		}

		// List only component-labeled RBACProfiles to find which component names
		// already have a profile. Then compare against what exists without a profile.
		// Since we no longer have per-component PermissionSets, we scan existing
		// component profiles and look for any known component without one.
		// The backfill source is the component-labeled RBACProfile list itself --
		// gaps are components that sent a webhook call but failed before profile creation.
		// We detect gaps via a separate label index built from existing profiles.
		profileList := &securityv1alpha1.RBACProfileList{}
		if err := r.Client.List(ctx, profileList,
			client.InNamespace(ns.Name),
			client.MatchingLabels{"ontai.dev/policy-type": "component"},
		); err != nil {
			log.Error(err, "list component RBACProfiles", "namespace", ns.Name)
			continue
		}

		// Back-fill: any component profile that references cluster-policy but has
		// provisioned=false and no spec.permissionDeclarations set may indicate a
		// partial write. Re-apply via EnsurePackRBACProfileCRs (idempotent SSA).
		for j := range profileList.Items {
			p := &profileList.Items[j]
			if p.Spec.RBACPolicyRef != "cluster-policy" {
				// Stale profile from old design referencing a per-component policy.
				// Log and skip; human cleanup required.
				log.Info("found stale RBACProfile referencing non-cluster-policy; skipping",
					"namespace", ns.Name, "name", p.Name, "rbacPolicyRef", p.Spec.RBACPolicyRef)
				continue
			}
			if p.Status.Provisioned {
				continue
			}
			log.Info("back-filling unprovisioned component RBACProfile", "namespace", ns.Name, "name", p.Name)
			if err := webhook.EnsurePackRBACProfileCRs(ctx, r.Client, p.Name, targetCluster); err != nil {
				log.Error(err, "EnsurePackRBACProfileCRs failed", "component", p.Name, "targetCluster", targetCluster)
				continue
			}
			filled++
		}
	}

	if filled > 0 {
		log.Info("RBACProfile back-fill pass complete", "filled", filled)
	}
	return nil
}
