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
// For each namespace it checks each PermissionSet for a missing RBACProfile and
// calls EnsurePackRBACProfileCRs for any gap found. Exported for unit testing.
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

		psList := &securityv1alpha1.PermissionSetList{}
		if err := r.Client.List(ctx, psList, client.InNamespace(ns.Name)); err != nil {
			log.Error(err, "list PermissionSets", "namespace", ns.Name)
			continue
		}

		for j := range psList.Items {
			componentName := psList.Items[j].Name

			profile := &securityv1alpha1.RBACProfile{}
			err := r.Client.Get(ctx, types.NamespacedName{Name: componentName, Namespace: ns.Name}, profile)
			if err == nil {
				continue
			}
			if !apierrors.IsNotFound(err) {
				log.Error(err, "get RBACProfile", "namespace", ns.Name, "name", componentName)
				continue
			}

			log.Info("back-filling RBACProfile CRs", "component", componentName, "targetCluster", targetCluster)
			if err := webhook.EnsurePackRBACProfileCRs(ctx, r.Client, componentName, targetCluster); err != nil {
				log.Error(err, "EnsurePackRBACProfileCRs failed", "component", componentName, "targetCluster", targetCluster)
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
