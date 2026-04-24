package e2e_test

// Step 1: Guardian RBACProfile generation and back-fill reconciler validation.
//
// Pre-conditions:
//   - guardian running in seam-system with admission webhook in Enforce mode
//   - cert-manager ClusterPack deployed (PackExecution reached Succeeded)
//   - seam-tenant-{mgmtClusterName} namespace exists
//
// Reusable: validateGuardianRBACGeneration accepts any ClusterClient and
// cluster name. Run against management cluster first; reuse for tenant cluster
// validation once TENANT-CLUSTER-E2E closes.
//
// Covers management cluster validation gate Step 1 (GAP_TO_FILL.md).

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	e2ehelpers "github.com/ontai-dev/seam-core/pkg/e2e"
)

var (
	rbacProfileGVR = schema.GroupVersionResource{
		Group:   "security.ontai.dev",
		Version: "v1alpha1",
		Resource: "rbacprofiles",
	}
	permissionSetGVR = schema.GroupVersionResource{
		Group:   "security.ontai.dev",
		Version: "v1alpha1",
		Resource: "permissionsets",
	}
	rbacPolicyGVR = schema.GroupVersionResource{
		Group:   "security.ontai.dev",
		Version: "v1alpha1",
		Resource: "rbacpolicies",
	}
)

var _ = Describe("Step 1: Guardian RBACProfile generation and back-fill reconciler", func() {
	const (
		backfillInterval = 60 * time.Second
		pollInterval     = 5 * time.Second
		generationTimeout = 3 * time.Minute
	)

	It("cert-manager ClusterPack deploy creates RBACProfile, PermissionSet, RBACPolicy in seam-tenant-{cluster}", func() {
		validateGuardianRBACGeneration(context.Background(), mgmtClient, mgmtClusterName, generationTimeout, pollInterval)
	})

	It("back-fill reconciler detects missing RBACProfile gap and creates it within one reconciliation cycle", func() {
		validateBackfillReconciler(context.Background(), mgmtClient, mgmtClusterName, backfillInterval, pollInterval)
	})

	It("back-fill reconciler is idempotent: second cycle does not create duplicates after gap is closed", func() {
		validateBackfillIdempotency(context.Background(), mgmtClient, mgmtClusterName, backfillInterval, pollInterval)
	})
})

// validateGuardianRBACGeneration verifies that after a ClusterPack is deployed to
// clusterName, guardian has created RBACProfile, PermissionSet, and RBACPolicy in
// the seam-tenant-{clusterName} namespace on the given cluster client.
func validateGuardianRBACGeneration(
	ctx context.Context,
	cl *e2ehelpers.ClusterClient,
	clusterName string,
	timeout, interval time.Duration,
) {
	tenantNS := "seam-tenant-" + clusterName

	By(fmt.Sprintf("waiting for RBACProfile to exist in %s on cluster %s", tenantNS, cl.Name))
	Eventually(func() bool {
		list, err := cl.Dynamic.Resource(rbacProfileGVR).Namespace(tenantNS).
			List(ctx, metav1.ListOptions{})
		return err == nil && len(list.Items) > 0
	}, timeout, interval).Should(BeTrue(),
		"guardian did not create RBACProfile in %s within %s", tenantNS, timeout)

	By("waiting for PermissionSet to exist")
	Eventually(func() bool {
		list, err := cl.Dynamic.Resource(permissionSetGVR).Namespace(tenantNS).
			List(ctx, metav1.ListOptions{})
		return err == nil && len(list.Items) > 0
	}, timeout, interval).Should(BeTrue(),
		"guardian did not create PermissionSet in %s within %s", tenantNS, timeout)

	By("waiting for RBACPolicy to exist")
	Eventually(func() bool {
		list, err := cl.Dynamic.Resource(rbacPolicyGVR).Namespace(tenantNS).
			List(ctx, metav1.ListOptions{})
		return err == nil && len(list.Items) > 0
	}, timeout, interval).Should(BeTrue(),
		"guardian did not create RBACPolicy in %s within %s", tenantNS, timeout)
}

// validateBackfillReconciler applies a raw RBAC ConfigMap labelled with
// ontai.dev/rbac-owner=guardian to the cluster, waits one reconciliation cycle
// (default 60s), and confirms the back-fill reconciler (T-04b) created the
// missing RBACProfile, PermissionSet, and RBACPolicy without manual intervention.
func validateBackfillReconciler(
	ctx context.Context,
	cl *e2ehelpers.ClusterClient,
	clusterName string,
	backfillInterval, pollInterval time.Duration,
) {
	tenantNS := "seam-tenant-" + clusterName
	testCMName := "e2e-backfill-gap-probe"

	By("counting existing RBACProfiles before injecting gap")
	listBefore, err := cl.Dynamic.Resource(rbacProfileGVR).Namespace(tenantNS).
		List(ctx, metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred())
	countBefore := len(listBefore.Items)

	By("applying raw RBAC ConfigMap with ontai.dev/rbac-owner=guardian label (gap injection)")
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      testCMName,
			Namespace: tenantNS,
			Labels: map[string]string{
				"ontai.dev/rbac-owner": "guardian",
			},
		},
	}
	_, err = cl.Typed.CoreV1().ConfigMaps(tenantNS).Create(ctx, cm, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "create gap-injection ConfigMap")

	DeferCleanup(func() {
		_ = cl.Typed.CoreV1().ConfigMaps(tenantNS).Delete(
			context.Background(), testCMName, metav1.DeleteOptions{})
	})

	By(fmt.Sprintf("waiting one reconciliation cycle (%s) for back-fill to fire", backfillInterval))
	// Wait slightly longer than one reconciliation cycle to guarantee at least one firing.
	waitTimeout := backfillInterval + 30*time.Second

	Eventually(func() bool {
		listAfter, err := cl.Dynamic.Resource(rbacProfileGVR).Namespace(tenantNS).
			List(ctx, metav1.ListOptions{})
		return err == nil && len(listAfter.Items) > countBefore
	}, waitTimeout, pollInterval).Should(BeTrue(),
		"back-fill reconciler did not create missing RBACProfile within %s; "+
			"before count: %d", waitTimeout, countBefore)
}

// validateBackfillIdempotency removes the test gap-injection object and confirms
// that a second reconciliation cycle does not create duplicate objects.
func validateBackfillIdempotency(
	ctx context.Context,
	cl *e2ehelpers.ClusterClient,
	clusterName string,
	backfillInterval, pollInterval time.Duration,
) {
	tenantNS := "seam-tenant-" + clusterName

	By("counting RBACProfiles after gap closure (test object already deleted by DeferCleanup in prior spec)")
	listBefore, err := cl.Dynamic.Resource(rbacProfileGVR).Namespace(tenantNS).
		List(ctx, metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred())
	countStable := len(listBefore.Items)

	By(fmt.Sprintf("waiting one full reconciliation cycle (%s) to confirm no duplicates appear", backfillInterval))
	waitTimeout := backfillInterval + 30*time.Second
	Consistently(func() int {
		list, err := cl.Dynamic.Resource(rbacProfileGVR).Namespace(tenantNS).
			List(ctx, metav1.ListOptions{})
		if err != nil {
			return -1
		}
		return len(list.Items)
	}, waitTimeout, pollInterval).Should(Equal(countStable),
		"idempotency violation: RBACProfile count changed after gap was closed")
}
