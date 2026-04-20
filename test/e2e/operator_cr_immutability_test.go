package e2e_test

// Scenario: Operator CR authorship guard blocks human modifications
//
// Pre-conditions required for this test to run:
//   - MGMT_KUBECONFIG set and pointing to a live ccs-mgmt cluster
//   - guardian operator running in seam-system with operator-cr webhook active
//   - At least one PackInstance, RunnerConfig, PermissionSnapshot, PackExecution
//     present in the cluster
//   - G-BL-CR-IMMUTABILITY closed (operator-cr-validating-webhook-configuration
//     deployed and caBundle populated by compiler enable)
//
// What this test verifies (G-BL-CR-IMMUTABILITY):
//   - A human principal (kubernetes-admin) cannot update PackInstance
//   - A human principal cannot update RunnerConfig
//   - A human principal cannot update PermissionSnapshot
//   - A human principal cannot update PackExecution
//   - The guardian service account (seam-system:guardian) can update all four
//   - The webhook error message references G-BL-CR-IMMUTABILITY

import (
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("operator CR authorship guard", func() {
	It("blocks human principal from updating PackInstance", func() {
		Skip("requires live cluster with MGMT_KUBECONFIG set and G-BL-CR-IMMUTABILITY closed")
	})

	It("blocks human principal from updating RunnerConfig", func() {
		Skip("requires live cluster with MGMT_KUBECONFIG set and G-BL-CR-IMMUTABILITY closed")
	})

	It("blocks human principal from updating PermissionSnapshot", func() {
		Skip("requires live cluster with MGMT_KUBECONFIG set and G-BL-CR-IMMUTABILITY closed")
	})

	It("blocks human principal from updating PackExecution", func() {
		Skip("requires live cluster with MGMT_KUBECONFIG set and G-BL-CR-IMMUTABILITY closed")
	})

	It("allows guardian service account to update all four protected kinds", func() {
		Skip("requires live cluster with MGMT_KUBECONFIG set and G-BL-CR-IMMUTABILITY closed")
	})

	It("webhook denial message references G-BL-CR-IMMUTABILITY", func() {
		Skip("requires live cluster with MGMT_KUBECONFIG set and G-BL-CR-IMMUTABILITY closed")
	})
})
