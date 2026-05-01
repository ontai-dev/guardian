package e2e_test

// tenant_snapshot_test.go -- live cluster verification for guardian role=tenant.
//
// Verifies the TenantSnapshotRunnable lifecycle and the RBACProfileReconciler
// tenant snapshot path on ccs-dev against the management cluster on ccs-mgmt.
//
// Pre-conditions:
//   - MGMT_KUBECONFIG set (management cluster, ccs-mgmt, guardian in seam-system).
//   - TENANT_KUBECONFIG set (tenant cluster, ccs-dev, guardian in ont-system).
//   - TENANT_CLUSTER_NAME=ccs-dev (overrides default ccs-test).
//   - Guardian role=tenant running on ccs-dev; initial runOnce already completed.
//   - PermissionSnapshot snapshot-{tenantClusterName} exists in seam-system on ccs-mgmt.
//   - cert-manager deployed to ccs-dev via ClusterPack.
//
// guardian-schema.md §7, §8, §15. GUARDIAN-BL-RBACPROFILE-TENANT-PROVISIONING.

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	e2ehelpers "github.com/ontai-dev/seam-core/pkg/e2e"
)

// tenantNSExists returns true if the given namespace exists on the given cluster.
func tenantNSExists(ctx context.Context, cl *e2ehelpers.ClusterClient, ns string) bool {
	_, err := cl.Typed.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	return err == nil
}

const (
	// mgmtGuardianNamespace is the namespace where guardian role=management runs on ccs-mgmt.
	mgmtGuardianNamespace = "seam-system"
	// tenantGuardianNamespace is the namespace where guardian role=tenant runs on ccs-dev.
	tenantGuardianNamespace = "ont-system"

	snapshotPollTimeout  = 3 * time.Minute
	snapshotPollInterval = 5 * time.Second
)

var (
	permissionSnapshotGVR = schema.GroupVersionResource{
		Group: "security.ontai.dev", Version: "v1alpha1", Resource: "permissionsnapshots",
	}
	permissionSnapshotReceiptGVR = schema.GroupVersionResource{
		Group: "security.ontai.dev", Version: "v1alpha1", Resource: "permissionsnapshotreceipts",
	}
)

var _ = Describe("Guardian role=tenant: TenantSnapshotRunnable lifecycle", func() {
	BeforeEach(func() {
		if tenantClient == nil {
			Skip("requires TENANT_KUBECONFIG and TENANT_CLUSTER_NAME=ccs-dev (GUARDIAN-TENANT-E2E)")
		}
	})

	It("PermissionSnapshotReceipt receipt-{tenantClusterName} exists in ont-system on tenant cluster", func() {
		receiptName := "receipt-" + tenantClusterName
		By(fmt.Sprintf("polling for PermissionSnapshotReceipt %s in %s on %s",
			receiptName, tenantGuardianNamespace, tenantClient.Name))

		Eventually(func() bool {
			_, err := tenantClient.Dynamic.Resource(permissionSnapshotReceiptGVR).
				Namespace(tenantGuardianNamespace).
				Get(context.Background(), receiptName, metav1.GetOptions{})
			return err == nil
		}, snapshotPollTimeout, snapshotPollInterval).Should(BeTrue(),
			"TenantSnapshotRunnable did not create %s/%s within %s",
			tenantGuardianNamespace, receiptName, snapshotPollTimeout)
	})

	It("receipt has snapshotVersion and acknowledgedAt set", func() {
		receiptName := "receipt-" + tenantClusterName
		receipt, err := tenantClient.Dynamic.Resource(permissionSnapshotReceiptGVR).
			Namespace(tenantGuardianNamespace).
			Get(context.Background(), receiptName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		spec, _ := receipt.Object["spec"].(map[string]interface{})
		Expect(spec).NotTo(BeNil(), "receipt must have spec")

		version, _ := spec["snapshotVersion"].(string)
		Expect(version).NotTo(BeEmpty(),
			"snapshotVersion must be set by TenantSnapshotRunnable")

		ackedAt, _ := spec["acknowledgedAt"].(string)
		Expect(ackedAt).NotTo(BeEmpty(),
			"acknowledgedAt must be set by TenantSnapshotRunnable")
	})

	It("local PermissionSnapshot mirror snapshot-{tenantClusterName} exists in ont-system with mirrored label", func() {
		mirrorName := "snapshot-" + tenantClusterName
		By(fmt.Sprintf("polling for local PermissionSnapshot mirror %s in %s on %s",
			mirrorName, tenantGuardianNamespace, tenantClient.Name))

		Eventually(func() bool {
			mirror, err := tenantClient.Dynamic.Resource(permissionSnapshotGVR).
				Namespace(tenantGuardianNamespace).
				Get(context.Background(), mirrorName, metav1.GetOptions{})
			if err != nil {
				return false
			}
			labels := mirror.GetLabels()
			return labels["ontai.dev/snapshot-type"] == "mirrored"
		}, snapshotPollTimeout, snapshotPollInterval).Should(BeTrue(),
			"local PermissionSnapshot mirror %s/%s with ontai.dev/snapshot-type=mirrored not found within %s",
			tenantGuardianNamespace, mirrorName, snapshotPollTimeout)
	})

	It("local mirror carries the full spec including version from management cluster", func() {
		mirrorName := "snapshot-" + tenantClusterName
		mirror, err := tenantClient.Dynamic.Resource(permissionSnapshotGVR).
			Namespace(tenantGuardianNamespace).
			Get(context.Background(), mirrorName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		spec, _ := mirror.Object["spec"].(map[string]interface{})
		Expect(spec).NotTo(BeNil(), "mirror must have spec")

		version, _ := spec["version"].(string)
		Expect(version).NotTo(BeEmpty(),
			"mirror spec must carry version from management cluster snapshot")

		targetCluster, _ := spec["targetCluster"].(string)
		Expect(targetCluster).To(Equal(tenantClusterName),
			"mirror spec.targetCluster must match this cluster")
	})
})

var _ = Describe("Guardian role=management: PermissionSnapshot Compliant condition for tenant", func() {
	It("management cluster PermissionSnapshot snapshot-{tenantClusterName} has Compliant=True", func() {
		snapshotName := "snapshot-" + tenantClusterName
		By(fmt.Sprintf("polling for Compliant=True on %s/%s on %s",
			mgmtGuardianNamespace, snapshotName, mgmtClient.Name))

		Eventually(func() bool {
			snap, err := mgmtClient.Dynamic.Resource(permissionSnapshotGVR).
				Namespace(mgmtGuardianNamespace).
				Get(context.Background(), snapshotName, metav1.GetOptions{})
			if err != nil {
				return false
			}
			return snapshotHasCompliantTrue(snap.Object)
		}, snapshotPollTimeout, snapshotPollInterval).Should(BeTrue(),
			"management cluster snapshot %s/%s did not reach Compliant=True within %s",
			mgmtGuardianNamespace, snapshotName, snapshotPollTimeout)
	})

	It("management cluster PermissionSnapshot has drift=false and lastAckedVersion set", func() {
		snapshotName := "snapshot-" + tenantClusterName
		snap, err := mgmtClient.Dynamic.Resource(permissionSnapshotGVR).
			Namespace(mgmtGuardianNamespace).
			Get(context.Background(), snapshotName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		status, _ := snap.Object["status"].(map[string]interface{})
		Expect(status).NotTo(BeNil(), "management snapshot must have status")

		drift, _ := status["drift"].(bool)
		Expect(drift).To(BeFalse(), "drift must be false after TenantSnapshotRunnable acknowledges")

		lastAcked, _ := status["lastAckedVersion"].(string)
		Expect(lastAcked).NotTo(BeEmpty(),
			"lastAckedVersion must be set by TenantSnapshotRunnable acknowledgement")
	})
})

var _ = Describe("Guardian role=tenant: RBACProfileReconciler tenant snapshot path", func() {
	BeforeEach(func() {
		if tenantClient == nil {
			Skip("requires TENANT_KUBECONFIG and TENANT_CLUSTER_NAME=ccs-dev (GUARDIAN-TENANT-E2E)")
		}
	})

	It("cert-manager RBACProfile exists in ont-system with empty RBACPolicyRef", func() {
		if !tenantNSExists(context.Background(), tenantClient, "cert-manager") {
			Skip("requires cert-manager deployed to tenant cluster and GUARDIAN-TENANT-E2E closed")
		}
		profile, err := tenantClient.Dynamic.Resource(rbacProfileGVR).
			Namespace(tenantGuardianNamespace).
			Get(context.Background(), "cert-manager", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred(),
			"cert-manager RBACProfile must exist in ont-system (TenantProfileRunnable)")

		spec, _ := profile.Object["spec"].(map[string]interface{})
		Expect(spec).NotTo(BeNil())

		policyRef, _ := spec["rbacPolicyRef"].(string)
		Expect(policyRef).To(BeEmpty(),
			"RBACPolicyRef must be empty on tenant cluster (governance ceiling is management cluster PermissionSnapshot)")
	})

	It("cert-manager RBACProfile has TargetClusters=[tenantClusterName]", func() {
		if !tenantNSExists(context.Background(), tenantClient, "cert-manager") {
			Skip("requires cert-manager deployed to tenant cluster and GUARDIAN-TENANT-E2E closed")
		}
		profile, err := tenantClient.Dynamic.Resource(rbacProfileGVR).
			Namespace(tenantGuardianNamespace).
			Get(context.Background(), "cert-manager", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		spec, _ := profile.Object["spec"].(map[string]interface{})
		targets, _ := spec["targetClusters"].([]interface{})
		Expect(targets).To(HaveLen(1))
		Expect(targets[0]).To(Equal(tenantClusterName),
			"TargetClusters must reference this cluster (set by TenantProfileRunnable)")
	})

	It("cert-manager RBACProfile reaches Provisioned=True via local mirror snapshot", func() {
		if !tenantNSExists(context.Background(), tenantClient, "cert-manager") {
			Skip("requires cert-manager deployed to tenant cluster and GUARDIAN-TENANT-E2E closed")
		}
		By("polling for Provisioned=True on cert-manager RBACProfile in ont-system")

		Eventually(func() bool {
			profile, err := tenantClient.Dynamic.Resource(rbacProfileGVR).
				Namespace(tenantGuardianNamespace).
				Get(context.Background(), "cert-manager", metav1.GetOptions{})
			if err != nil {
				return false
			}
			status, _ := profile.Object["status"].(map[string]interface{})
			if status == nil {
				return false
			}
			provisioned, _ := status["provisioned"].(bool)
			return provisioned
		}, snapshotPollTimeout, snapshotPollInterval).Should(BeTrue(),
			"cert-manager RBACProfile must reach Provisioned=True via tenant snapshot path within %s",
			snapshotPollTimeout)
	})

	It("component RBACProfile audit label links to component name", func() {
		if !tenantNSExists(context.Background(), tenantClient, "cert-manager") {
			Skip("requires cert-manager deployed to tenant cluster and GUARDIAN-TENANT-E2E closed")
		}
		profile, err := tenantClient.Dynamic.Resource(rbacProfileGVR).
			Namespace(tenantGuardianNamespace).
			Get(context.Background(), "cert-manager", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		componentLabel := profile.GetLabels()["ontai.dev/component"]
		Expect(componentLabel).To(Equal("cert-manager"),
			"RBACProfile must carry ontai.dev/component label linking it to the swept component (audit requirement)")

		policyTypeLabel := profile.GetLabels()["ontai.dev/policy-type"]
		Expect(policyTypeLabel).To(Equal("component"),
			"RBACProfile must carry ontai.dev/policy-type=component label")
	})
})

// snapshotHasCompliantTrue traverses status.conditions to find type=Compliant with status=True.
func snapshotHasCompliantTrue(obj map[string]interface{}) bool {
	status, _ := obj["status"].(map[string]interface{})
	if status == nil {
		return false
	}
	conditions, _ := status["conditions"].([]interface{})
	for _, raw := range conditions {
		cond, _ := raw.(map[string]interface{})
		if cond == nil {
			continue
		}
		if cond["type"] == "Compliant" && cond["status"] == "True" {
			return true
		}
	}
	return false
}
