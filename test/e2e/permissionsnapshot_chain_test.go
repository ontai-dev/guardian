package e2e_test

// permissionsnapshot_chain_test.go -- live cluster verification of the management
// cluster RBAC governance chain for tenant clusters.
//
// Verifies:
//   1. ClusterRBACPolicyReconciler created cluster-policy + cluster-maximum in
//      seam-tenant-{tenantClusterName} on the management cluster.
//   2. EPGController generated PermissionSnapshot snapshot-{tenantClusterName}
//      in seam-system on the management cluster.
//   3. Third-party component RBACProfiles exist in seam-tenant-{tenantClusterName}
//      (created by cert-manager ClusterPack deployment path, confirmed via guardian).
//
// Pre-conditions:
//   - MGMT_KUBECONFIG set.
//   - TENANT_CLUSTER_NAME=ccs-dev.
//   - Guardian role=management running in seam-system on ccs-mgmt.
//   - cert-manager ClusterPack deployed to ccs-dev (PackExecution Succeeded).
//
// CS-INV-008. guardian-schema.md §7, §15, §19.

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	chainPollTimeout  = 3 * time.Minute
	chainPollInterval = 5 * time.Second
)

var _ = Describe("Management cluster: ClusterRBACPolicy chain for tenant", func() {
	It("seam-tenant-{tenantClusterName} namespace exists on management cluster", func() {
		tenantNS := "seam-tenant-" + tenantClusterName
		By(fmt.Sprintf("verifying namespace %s exists on %s", tenantNS, mgmtClient.Name))
		_, err := mgmtClient.Typed.CoreV1().Namespaces().Get(
			context.Background(), tenantNS, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred(),
			"ClusterRBACPolicyReconciler must have created namespace %s", tenantNS)
	})

	It("cluster-policy RBACPolicy exists in seam-tenant-{tenantClusterName}", func() {
		tenantNS := "seam-tenant-" + tenantClusterName
		By(fmt.Sprintf("verifying cluster-policy RBACPolicy in %s", tenantNS))

		Eventually(func() bool {
			_, err := mgmtClient.Dynamic.Resource(rbacPolicyGVR).
				Namespace(tenantNS).
				Get(context.Background(), "cluster-policy", metav1.GetOptions{})
			return err == nil
		}, chainPollTimeout, chainPollInterval).Should(BeTrue(),
			"ClusterRBACPolicyReconciler did not create cluster-policy in %s within %s",
			tenantNS, chainPollTimeout)
	})

	It("cluster-maximum PermissionSet exists in seam-tenant-{tenantClusterName}", func() {
		tenantNS := "seam-tenant-" + tenantClusterName
		By(fmt.Sprintf("verifying cluster-maximum PermissionSet in %s", tenantNS))

		Eventually(func() bool {
			_, err := mgmtClient.Dynamic.Resource(permissionSetGVR).
				Namespace(tenantNS).
				Get(context.Background(), "cluster-maximum", metav1.GetOptions{})
			return err == nil
		}, chainPollTimeout, chainPollInterval).Should(BeTrue(),
			"ClusterRBACPolicyReconciler did not create cluster-maximum in %s within %s",
			tenantNS, chainPollTimeout)
	})

	It("cluster-policy references cluster-maximum as its permission ceiling", func() {
		tenantNS := "seam-tenant-" + tenantClusterName
		policy, err := mgmtClient.Dynamic.Resource(rbacPolicyGVR).
			Namespace(tenantNS).
			Get(context.Background(), "cluster-policy", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		spec, _ := policy.Object["spec"].(map[string]interface{})
		Expect(spec).NotTo(BeNil())
		ceilingRef, _ := spec["maximumPermissionSetRef"].(string)
		Expect(ceilingRef).To(Equal("cluster-maximum"),
			"cluster-policy must reference cluster-maximum as the permission ceiling (CS-INV-008)")
	})

	It("cert-manager RBACProfile exists in seam-tenant-{tenantClusterName} after ClusterPack deploy", func() {
		tenantNS := "seam-tenant-" + tenantClusterName
		By(fmt.Sprintf("verifying cert-manager RBACProfile in %s", tenantNS))

		Eventually(func() bool {
			_, err := mgmtClient.Dynamic.Resource(rbacProfileGVR).
				Namespace(tenantNS).
				Get(context.Background(), "cert-manager", metav1.GetOptions{})
			return err == nil
		}, chainPollTimeout, chainPollInterval).Should(BeTrue(),
			"cert-manager RBACProfile not found in %s — guardian /rbac-intake/pack did not create it within %s",
			tenantNS, chainPollTimeout)
	})

	It("cert-manager RBACProfile in seam-tenant-{tenantClusterName} references cluster-policy", func() {
		tenantNS := "seam-tenant-" + tenantClusterName
		profile, err := mgmtClient.Dynamic.Resource(rbacProfileGVR).
			Namespace(tenantNS).
			Get(context.Background(), "cert-manager", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		spec, _ := profile.Object["spec"].(map[string]interface{})
		Expect(spec).NotTo(BeNil())
		policyRef, _ := spec["rbacPolicyRef"].(string)
		Expect(policyRef).To(Equal("cluster-policy"),
			"management cluster RBACProfile must reference cluster-policy (Layer 2 ceiling)")
	})
})

var _ = Describe("Management cluster: PermissionSnapshot generation for tenant", func() {
	It("PermissionSnapshot snapshot-{tenantClusterName} exists in seam-system", func() {
		snapshotName := "snapshot-" + tenantClusterName
		By(fmt.Sprintf("polling for %s/%s on %s", mgmtGuardianNamespace, snapshotName, mgmtClient.Name))

		Eventually(func() bool {
			_, err := mgmtClient.Dynamic.Resource(permissionSnapshotGVR).
				Namespace(mgmtGuardianNamespace).
				Get(context.Background(), snapshotName, metav1.GetOptions{})
			return err == nil
		}, chainPollTimeout, chainPollInterval).Should(BeTrue(),
			"EPGController did not generate snapshot %s/%s within %s",
			mgmtGuardianNamespace, snapshotName, chainPollTimeout)
	})

	It("PermissionSnapshot spec.targetCluster matches tenantClusterName", func() {
		snapshotName := "snapshot-" + tenantClusterName
		snap, err := mgmtClient.Dynamic.Resource(permissionSnapshotGVR).
			Namespace(mgmtGuardianNamespace).
			Get(context.Background(), snapshotName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		spec, _ := snap.Object["spec"].(map[string]interface{})
		Expect(spec).NotTo(BeNil())
		target, _ := spec["targetCluster"].(string)
		Expect(target).To(Equal(tenantClusterName),
			"PermissionSnapshot must be scoped to tenant cluster %s", tenantClusterName)
	})

	It("PermissionSnapshot spec.version is non-empty", func() {
		snapshotName := "snapshot-" + tenantClusterName
		snap, err := mgmtClient.Dynamic.Resource(permissionSnapshotGVR).
			Namespace(mgmtGuardianNamespace).
			Get(context.Background(), snapshotName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		spec, _ := snap.Object["spec"].(map[string]interface{})
		version, _ := spec["version"].(string)
		Expect(version).NotTo(BeEmpty(),
			"EPGController must set spec.version when generating the PermissionSnapshot")
	})

	It("PermissionSnapshot carries conductor signing annotation (signing loop ran)", func() {
		snapshotName := "snapshot-" + tenantClusterName
		snap, err := mgmtClient.Dynamic.Resource(permissionSnapshotGVR).
			Namespace(mgmtGuardianNamespace).
			Get(context.Background(), snapshotName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		sig := snap.GetAnnotations()["ontai.dev/pack-signature"]
		Expect(sig).NotTo(BeEmpty(),
			"Conductor signing loop must have set ontai.dev/pack-signature on PermissionSnapshot (INV-026)")
	})
})
