package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

var (
	snapshotGVR = schema.GroupVersionResource{
		Group:   "security.ontai.dev",
		Version: "v1alpha1",
		Resource: "permissionsnapshots",
	}
	snapshotReceiptGVR = schema.GroupVersionResource{
		Group:   "security.ontai.dev",
		Version: "v1alpha1",
		Resource: "permissionsnapshotreceipts",
	}
)

// LabelSnapshotTypeMirrored is applied to the local PermissionSnapshot mirror
// written by TenantSnapshotRunnable in ont-system. Distinguishes the mirror from
// management-authored snapshots. Read by RBACProfileReconciler tenant path.
const LabelSnapshotTypeMirrored = "mirrored"

// LabelKeySnapshotType is the label key used to identify mirrored snapshots.
const LabelKeySnapshotType = "ontai.dev/snapshot-type"

// TenantSnapshotRunnable is a manager.Runnable (requires leader election) that:
//
//  1. Pulls the PermissionSnapshot for ClusterID from the management cluster.
//  2. Writes / updates the local PermissionSnapshotReceipt in Namespace.
//  2a. Upserts a local PermissionSnapshot mirror in Namespace (enforcement reference).
//  3. Patches lastAckedVersion + lastSeen on the management PermissionSnapshot status.
//  4. Sets the Compliant condition on the management PermissionSnapshot.
//
// Guardian role=tenant exclusively owns all security.ontai.dev receipt and compliance
// operations on the tenant cluster. guardian-schema.md §7, §8, §15.
type TenantSnapshotRunnable struct {
	// LocalClient is the controller-runtime client scoped to the tenant cluster.
	LocalClient client.Client

	// MgmtClient is the dynamic client for the management cluster.
	// Used to list PermissionSnapshots and patch acknowledgement status.
	MgmtClient dynamic.Interface

	// ClusterID is this tenant cluster's name, e.g. "ccs-dev".
	ClusterID string

	// Namespace is the local operator namespace where the receipt is written (ont-system).
	Namespace string

	// Interval is the reconcile period.
	Interval time.Duration
}

// NeedLeaderElection satisfies manager.LeaderElectionRunnable.
// Only the leader writes receipts and acknowledgements.
func (r *TenantSnapshotRunnable) NeedLeaderElection() bool { return true }

// Start satisfies manager.Runnable. Runs until ctx is cancelled.
func (r *TenantSnapshotRunnable) Start(ctx context.Context) error {
	log := ctrl.Log.WithName("tenant-snapshot-runnable").WithValues("cluster", r.ClusterID)
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

func (r *TenantSnapshotRunnable) runOnce(ctx context.Context) {
	log := ctrl.Log.WithName("tenant-snapshot-runnable").WithValues("cluster", r.ClusterID)

	// Step 1 — Pull PermissionSnapshot from management cluster.
	list, err := r.MgmtClient.Resource(snapshotGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Error(err, "list PermissionSnapshots from management cluster")
		return
	}

	var snapshotName, version, mgmtNamespace string
	var snapSpecMap map[string]interface{}
	var found bool
	for _, item := range list.Items {
		spec, ok := item.Object["spec"].(map[string]interface{})
		if !ok {
			continue
		}
		if tc, _ := spec["targetCluster"].(string); tc != r.ClusterID {
			continue
		}
		snapshotName = item.GetName()
		mgmtNamespace = item.GetNamespace()
		version, _ = spec["version"].(string)
		snapSpecMap = spec
		found = true
		break
	}
	if !found {
		log.Info("no PermissionSnapshot for this cluster found on management cluster")
		return
	}

	// Step 2 — Write / update local PermissionSnapshotReceipt.
	if err := r.ensureLocalReceipt(ctx, snapshotName, version); err != nil {
		log.Error(err, "ensure local PermissionSnapshotReceipt", "snapshot", snapshotName)
		return
	}

	// Step 2a — Upsert local PermissionSnapshot mirror in Namespace.
	// This is the enforcement reference read by RBACProfileReconciler (tenant path)
	// and in future by the admission webhook for RBAC ceiling validation.
	// The mirror carries the full Subjects permission content from the management snapshot.
	if err := r.upsertLocalSnapshot(ctx, snapSpecMap); err != nil {
		log.Error(err, "upsert local PermissionSnapshot mirror", "snapshot", snapshotName)
		return
	}

	// Step 3 — Acknowledge on management cluster.
	if err := r.acknowledgeOnManagement(ctx, mgmtNamespace, snapshotName, version); err != nil {
		log.Error(err, "acknowledge on management cluster", "snapshot", snapshotName)
		return
	}

	// Step 4 — Set Compliant condition on management PermissionSnapshot.
	if err := r.setCompliant(ctx, mgmtNamespace, snapshotName); err != nil {
		log.Error(err, "set Compliant condition", "snapshot", snapshotName)
		return
	}

	log.Info("snapshot receipt reconciled", "snapshot", snapshotName, "version", version)
}

// upsertLocalSnapshot creates or updates a PermissionSnapshot mirror in Namespace.
// The mirror carries the full spec (including Subjects permission content) from the
// management cluster snapshot. It is labeled ontai.dev/snapshot-type=mirrored so
// the RBACProfileReconciler tenant path can distinguish it from management snapshots.
// This is the local enforcement reference for the tenant cluster. guardian-schema.md §7.
func (r *TenantSnapshotRunnable) upsertLocalSnapshot(ctx context.Context, specMap map[string]interface{}) error {
	specJSON, err := json.Marshal(specMap)
	if err != nil {
		return fmt.Errorf("marshal snapshot spec: %w", err)
	}
	var spec securityv1alpha1.PermissionSnapshotSpec
	if err := json.Unmarshal(specJSON, &spec); err != nil {
		return fmt.Errorf("unmarshal snapshot spec: %w", err)
	}

	localName := "snapshot-" + r.ClusterID
	existing := &securityv1alpha1.PermissionSnapshot{}
	err = r.LocalClient.Get(ctx, client.ObjectKey{Namespace: r.Namespace, Name: localName}, existing)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("get local snapshot: %w", err)
	}

	if apierrors.IsNotFound(err) {
		mirror := &securityv1alpha1.PermissionSnapshot{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: r.Namespace,
				Name:      localName,
				Labels: map[string]string{
					LabelKeyManagedBy:    LabelManagedByGuardian,
					LabelKeySnapshotType: LabelSnapshotTypeMirrored,
				},
			},
			Spec: spec,
		}
		return r.LocalClient.Create(ctx, mirror)
	}

	if existing.Spec.Version == spec.Version {
		return nil
	}
	patch := client.MergeFrom(existing.DeepCopy())
	existing.Spec = spec
	return r.LocalClient.Patch(ctx, existing, patch)
}

// ensureLocalReceipt creates or updates the PermissionSnapshotReceipt in Namespace.
func (r *TenantSnapshotRunnable) ensureLocalReceipt(ctx context.Context, snapshotName, version string) error {
	receipt := &securityv1alpha1.PermissionSnapshotReceipt{}
	receiptName := "receipt-" + r.ClusterID
	err := r.LocalClient.Get(ctx, client.ObjectKey{Namespace: r.Namespace, Name: receiptName}, receipt)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("get receipt: %w", err)
	}

	if apierrors.IsNotFound(err) {
		receipt = &securityv1alpha1.PermissionSnapshotReceipt{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: r.Namespace,
				Name:      receiptName,
				Labels: map[string]string{
					LabelKeyManagedBy: LabelManagedByGuardian,
				},
			},
			Spec: securityv1alpha1.PermissionSnapshotReceiptSpec{
				ClusterName:     r.ClusterID,
				SnapshotVersion: version,
				AcknowledgedAt:  metav1.Now(),
			},
		}
		if createErr := r.LocalClient.Create(ctx, receipt); createErr != nil {
			return fmt.Errorf("create receipt: %w", createErr)
		}
		if err := r.LocalClient.Status().Patch(ctx, receipt, client.MergeFrom(receipt.DeepCopy()), client.FieldOwner("guardian-tenant")); err != nil {
			// Non-fatal: status will be updated on next cycle.
			ctrl.Log.WithName("tenant-snapshot-runnable").Error(err, "patch receipt status after create")
		}
		return nil
	}

	// Update spec if version changed.
	if receipt.Spec.SnapshotVersion == version {
		return nil
	}
	patch := client.MergeFrom(receipt.DeepCopy())
	receipt.Spec.SnapshotVersion = version
	receipt.Spec.AcknowledgedAt = metav1.Now()
	return r.LocalClient.Patch(ctx, receipt, patch)
}

// acknowledgeOnManagement patches lastAckedVersion and lastSeen on the management
// cluster PermissionSnapshot status. This clears drift=true.
func (r *TenantSnapshotRunnable) acknowledgeOnManagement(ctx context.Context, ns, name, version string) error {
	now := metav1.Now()
	patch := map[string]interface{}{
		"status": map[string]interface{}{
			"lastAckedVersion": version,
			"lastSeen":         now.UTC().Format(time.RFC3339),
			"drift":            false,
		},
	}
	data, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshal ack patch: %w", err)
	}
	_, err = r.MgmtClient.Resource(snapshotGVR).Namespace(ns).Patch(
		ctx, name, types.MergePatchType, data, metav1.PatchOptions{}, "status",
	)
	return err
}

// setCompliant sets Compliant=True on the management cluster PermissionSnapshot status.
// A receipt that has been written and acknowledged means the tenant has the current
// snapshot and is operating within its declared permissions. guardian-schema.md §7.
func (r *TenantSnapshotRunnable) setCompliant(ctx context.Context, ns, name string) error {
	now := metav1.Now().UTC().Format(time.RFC3339)
	condition := map[string]interface{}{
		"type":               "Compliant",
		"status":             "True",
		"reason":             "SnapshotAcknowledged",
		"message":            fmt.Sprintf("Tenant cluster %q has acknowledged the current snapshot.", r.ClusterID),
		"lastTransitionTime": now,
	}
	patch := map[string]interface{}{
		"status": map[string]interface{}{
			"conditions": []interface{}{condition},
		},
	}
	data, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshal compliant patch: %w", err)
	}
	_, err = r.MgmtClient.Resource(snapshotGVR).Namespace(ns).Patch(
		ctx, name, types.MergePatchType, data, metav1.PatchOptions{}, "status",
	)
	return err
}
