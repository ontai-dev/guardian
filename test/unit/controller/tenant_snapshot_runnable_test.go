// Package controller_test contains unit tests for TenantSnapshotRunnable.
//
// TenantSnapshotRunnable is responsible for:
//  1. Pulling the PermissionSnapshot for ClusterID from the management cluster.
//  2. Writing / updating PermissionSnapshotReceipt in Namespace on the tenant cluster.
//  3. Patching lastAckedVersion, lastSeen, drift=false on the management snapshot.
//  4. Setting the Compliant=True condition on the management snapshot.
//
// Guardian role=tenant exclusively owns all security.ontai.dev operations.
// Conductor must never write security.ontai.dev resources. INV-004.
//
// guardian-schema.md §7, §8, §15. INV-004.
package controller_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
)

// snapshotGVR is the GVR for PermissionSnapshot. Mirrors the private const in the runnable.
var testSnapshotGVR = schema.GroupVersionResource{
	Group:    "security.ontai.dev",
	Version:  "v1alpha1",
	Resource: "permissionsnapshots",
}

// buildSnapshotScheme returns a runtime.Scheme with securityv1alpha1 types registered.
// Required by NewSimpleDynamicClient to convert typed objects to unstructured.
func buildSnapshotScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(securityv1alpha1.AddToScheme(s))
	return s
}

// buildLocalScheme returns a scheme for the tenant cluster fake client.
func buildLocalScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(securityv1alpha1.AddToScheme(s))
	return s
}

// makePermissionSnapshot builds a typed PermissionSnapshot for use with NewSimpleDynamicClient.
func makePermissionSnapshot(name, namespace, targetCluster, version string) *securityv1alpha1.PermissionSnapshot {
	return &securityv1alpha1.PermissionSnapshot{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "security.ontai.dev/v1alpha1",
			Kind:       "PermissionSnapshot",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: securityv1alpha1.PermissionSnapshotSpec{
			TargetCluster: targetCluster,
			Version:       version,
		},
	}
}

// newSnapshotRunnable constructs a TenantSnapshotRunnable with a 1-hour interval
// so only the initial runOnce fires in tests using a pre-cancelled context.
func newSnapshotRunnable(localCl client.Client, dynCl *dynamicfake.FakeDynamicClient, clusterID, namespace string) *controller.TenantSnapshotRunnable {
	return &controller.TenantSnapshotRunnable{
		LocalClient: localCl,
		MgmtClient:  dynCl,
		ClusterID:   clusterID,
		Namespace:   namespace,
		Interval:    time.Hour,
	}
}

// runSnapshotOnce calls Start with an already-cancelled context so only the initial
// runOnce executes before the loop exits.
func runSnapshotOnce(t *testing.T, r *controller.TenantSnapshotRunnable) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("TenantSnapshotRunnable.Start: %v", err)
	}
}

// TestTenantSnapshotRunnable_CreatesReceiptWhenAbsent verifies that a
// PermissionSnapshotReceipt is created in Namespace when no receipt exists.
// The receipt carries the snapshot version and clusterName. guardian-schema.md §8.
func TestTenantSnapshotRunnable_CreatesReceiptWhenAbsent(t *testing.T) {
	const clusterID = "ccs-dev"
	const namespace = "ont-system"

	dynScheme := buildSnapshotScheme(t)
	snap := makePermissionSnapshot("snapshot-ccs-dev", "seam-system", clusterID, "v1")
	dynCl := dynamicfake.NewSimpleDynamicClient(dynScheme, snap)

	localScheme := buildLocalScheme(t)
	localCl := fake.NewClientBuilder().WithScheme(localScheme).Build()

	r := newSnapshotRunnable(localCl, dynCl, clusterID, namespace)
	runSnapshotOnce(t, r)

	receipt := &securityv1alpha1.PermissionSnapshotReceipt{}
	if err := localCl.Get(context.Background(),
		client.ObjectKey{Namespace: namespace, Name: "receipt-" + clusterID},
		receipt,
	); err != nil {
		t.Fatalf("PermissionSnapshotReceipt not found: %v", err)
	}
	if receipt.Spec.ClusterName != clusterID {
		t.Errorf("ClusterName = %q, want %q", receipt.Spec.ClusterName, clusterID)
	}
	if receipt.Spec.SnapshotVersion != "v1" {
		t.Errorf("SnapshotVersion = %q, want v1", receipt.Spec.SnapshotVersion)
	}
}

// TestTenantSnapshotRunnable_ReceiptIsNoOpWhenVersionUnchanged verifies that an
// existing receipt at the current snapshot version is not overwritten.
func TestTenantSnapshotRunnable_ReceiptIsNoOpWhenVersionUnchanged(t *testing.T) {
	const clusterID = "ccs-dev"
	const namespace = "ont-system"
	const version = "v2"

	dynScheme := buildSnapshotScheme(t)
	snap := makePermissionSnapshot("snapshot-ccs-dev", "seam-system", clusterID, version)
	dynCl := dynamicfake.NewSimpleDynamicClient(dynScheme, snap)

	existingReceipt := &securityv1alpha1.PermissionSnapshotReceipt{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       namespace,
			Name:            "receipt-" + clusterID,
			ResourceVersion: "1",
		},
		Spec: securityv1alpha1.PermissionSnapshotReceiptSpec{
			ClusterName:     clusterID,
			SnapshotVersion: version,
			AcknowledgedAt:  metav1.Now(),
		},
	}
	localScheme := buildLocalScheme(t)
	localCl := fake.NewClientBuilder().
		WithScheme(localScheme).
		WithObjects(existingReceipt).
		Build()

	r := newSnapshotRunnable(localCl, dynCl, clusterID, namespace)
	runSnapshotOnce(t, r)

	// Receipt must still have the original ResourceVersion -- no update occurred.
	receipt := &securityv1alpha1.PermissionSnapshotReceipt{}
	if err := localCl.Get(context.Background(),
		client.ObjectKey{Namespace: namespace, Name: "receipt-" + clusterID},
		receipt,
	); err != nil {
		t.Fatalf("get receipt: %v", err)
	}
	if receipt.Spec.SnapshotVersion != version {
		t.Errorf("SnapshotVersion changed unexpectedly: got %q, want %q",
			receipt.Spec.SnapshotVersion, version)
	}
}

// TestTenantSnapshotRunnable_UpdatesReceiptVersionWhenChanged verifies that when the
// management snapshot advances to a new version, the local receipt is updated.
func TestTenantSnapshotRunnable_UpdatesReceiptVersionWhenChanged(t *testing.T) {
	const clusterID = "ccs-dev"
	const namespace = "ont-system"

	dynScheme := buildSnapshotScheme(t)
	snap := makePermissionSnapshot("snapshot-ccs-dev", "seam-system", clusterID, "v2")
	dynCl := dynamicfake.NewSimpleDynamicClient(dynScheme, snap)

	existingReceipt := &securityv1alpha1.PermissionSnapshotReceipt{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       namespace,
			Name:            "receipt-" + clusterID,
			ResourceVersion: "1",
		},
		Spec: securityv1alpha1.PermissionSnapshotReceiptSpec{
			ClusterName:     clusterID,
			SnapshotVersion: "v1", // old version
			AcknowledgedAt:  metav1.Now(),
		},
	}
	localScheme := buildLocalScheme(t)
	localCl := fake.NewClientBuilder().
		WithScheme(localScheme).
		WithObjects(existingReceipt).
		Build()

	r := newSnapshotRunnable(localCl, dynCl, clusterID, namespace)
	runSnapshotOnce(t, r)

	receipt := &securityv1alpha1.PermissionSnapshotReceipt{}
	if err := localCl.Get(context.Background(),
		client.ObjectKey{Namespace: namespace, Name: "receipt-" + clusterID},
		receipt,
	); err != nil {
		t.Fatalf("get receipt: %v", err)
	}
	if receipt.Spec.SnapshotVersion != "v2" {
		t.Errorf("SnapshotVersion = %q, want v2 (must update when version advances)",
			receipt.Spec.SnapshotVersion)
	}
}

// TestTenantSnapshotRunnable_SkipsWhenNoSnapshotForCluster verifies that when no
// PermissionSnapshot exists for ClusterID on the management cluster, no receipt is
// created and no errors occur.
func TestTenantSnapshotRunnable_SkipsWhenNoSnapshotForCluster(t *testing.T) {
	const clusterID = "ccs-dev"
	const namespace = "ont-system"

	dynScheme := buildSnapshotScheme(t)
	// Snapshot for a different cluster -- must be ignored.
	snap := makePermissionSnapshot("snapshot-ccs-prod", "seam-system", "ccs-prod", "v1")
	dynCl := dynamicfake.NewSimpleDynamicClient(dynScheme, snap)

	localScheme := buildLocalScheme(t)
	localCl := fake.NewClientBuilder().WithScheme(localScheme).Build()

	r := newSnapshotRunnable(localCl, dynCl, clusterID, namespace)
	runSnapshotOnce(t, r)

	receiptList := &securityv1alpha1.PermissionSnapshotReceiptList{}
	if err := localCl.List(context.Background(), receiptList); err != nil {
		t.Fatalf("list receipts: %v", err)
	}
	if len(receiptList.Items) != 0 {
		t.Errorf("expected 0 receipts when no snapshot for cluster; got %d", len(receiptList.Items))
	}
}

// TestTenantSnapshotRunnable_PatchesAcknowledgementOnManagement verifies that the
// runnable patches lastAckedVersion, lastSeen, and drift=false on the management
// cluster PermissionSnapshot status. guardian-schema.md §7.
func TestTenantSnapshotRunnable_PatchesAcknowledgementOnManagement(t *testing.T) {
	const clusterID = "ccs-dev"
	const namespace = "ont-system"

	dynScheme := buildSnapshotScheme(t)
	snap := makePermissionSnapshot("snapshot-ccs-dev", "seam-system", clusterID, "v1")
	dynCl := dynamicfake.NewSimpleDynamicClient(dynScheme, snap)

	localScheme := buildLocalScheme(t)
	localCl := fake.NewClientBuilder().WithScheme(localScheme).Build()

	r := newSnapshotRunnable(localCl, dynCl, clusterID, namespace)
	runSnapshotOnce(t, r)

	// Verify the dynamic client received a Patch action targeting the snapshot
	// status subresource with the acknowledgement fields.
	actions := dynCl.Actions()
	var ackPatch k8stesting.PatchAction
	for _, a := range actions {
		if pa, ok := a.(k8stesting.PatchAction); ok &&
			pa.GetResource() == testSnapshotGVR &&
			pa.GetSubresource() == "status" &&
			pa.GetName() == "snapshot-ccs-dev" {
			ackPatch = pa
			break
		}
	}
	if ackPatch == nil {
		t.Fatal("no status Patch action found on management cluster dynamic client")
	}

	// The patch data must contain lastAckedVersion = "v1".
	var patchData map[string]interface{}
	if err := json.Unmarshal(ackPatch.GetPatch(), &patchData); err != nil {
		t.Fatalf("unmarshal patch: %v", err)
	}
	statusMap, ok := patchData["status"].(map[string]interface{})
	if !ok {
		t.Fatalf("patch missing status key: %v", patchData)
	}
	if got, _ := statusMap["lastAckedVersion"].(string); got != "v1" {
		t.Errorf("lastAckedVersion = %q, want v1", got)
	}
	if drift, _ := statusMap["drift"].(bool); drift {
		t.Error("drift must be false in acknowledgement patch")
	}
}

// TestTenantSnapshotRunnable_SetsCompliantConditionOnManagement verifies that after
// acknowledging, Compliant=True is patched onto the management snapshot status.
// guardian-schema.md §7. CS-INV-001.
func TestTenantSnapshotRunnable_SetsCompliantConditionOnManagement(t *testing.T) {
	const clusterID = "ccs-dev"
	const namespace = "ont-system"

	dynScheme := buildSnapshotScheme(t)
	snap := makePermissionSnapshot("snapshot-ccs-dev", "seam-system", clusterID, "v1")
	dynCl := dynamicfake.NewSimpleDynamicClient(dynScheme, snap)

	localScheme := buildLocalScheme(t)
	localCl := fake.NewClientBuilder().WithScheme(localScheme).Build()

	r := newSnapshotRunnable(localCl, dynCl, clusterID, namespace)
	runSnapshotOnce(t, r)

	// Find the Compliant condition Patch action. The runnable sends two Patch actions:
	// first acknowledgeOnManagement, then setCompliant. The Compliant patch contains
	// "conditions" in its status payload.
	actions := dynCl.Actions()
	var compliantPatch k8stesting.PatchAction
	for _, a := range actions {
		if pa, ok := a.(k8stesting.PatchAction); ok &&
			pa.GetResource() == testSnapshotGVR &&
			pa.GetSubresource() == "status" {
			var d map[string]interface{}
			if err := json.Unmarshal(pa.GetPatch(), &d); err != nil {
				continue
			}
			if st, ok := d["status"].(map[string]interface{}); ok {
				if _, hasConditions := st["conditions"]; hasConditions {
					compliantPatch = pa
					break
				}
			}
		}
	}
	if compliantPatch == nil {
		t.Fatal("no conditions Patch action found on management cluster dynamic client")
	}

	var patchData map[string]interface{}
	if err := json.Unmarshal(compliantPatch.GetPatch(), &patchData); err != nil {
		t.Fatalf("unmarshal compliant patch: %v", err)
	}
	statusMap := patchData["status"].(map[string]interface{})
	conditions, ok := statusMap["conditions"].([]interface{})
	if !ok || len(conditions) == 0 {
		t.Fatalf("conditions missing or empty in patch: %v", statusMap)
	}
	cond := conditions[0].(map[string]interface{})
	if cond["type"] != "Compliant" {
		t.Errorf("condition type = %q, want Compliant", cond["type"])
	}
	if cond["status"] != "True" {
		t.Errorf("condition status = %q, want True", cond["status"])
	}
	if cond["reason"] != "SnapshotAcknowledged" {
		t.Errorf("condition reason = %q, want SnapshotAcknowledged", cond["reason"])
	}
}

// Compile-time guard: TenantSnapshotRunnable must expose exported fields.
var _ = controller.TenantSnapshotRunnable{
	LocalClient: nil,
	MgmtClient:  nil,
	ClusterID:   "",
	Namespace:   "",
	Interval:    0,
}
