package e2e_test

// Scenario: RBACProfile enforcement
//
// Pre-conditions required for this test to run:
//   - ccs-mgmt fully provisioned (MGMT_KUBECONFIG set)
//   - guardian running in seam-system; webhook in Enforce mode
//   - A governing RBACPolicy exists in security-system on ccs-mgmt
//   - seam-tenant-ccs-test namespace exists (Platform created it)
//
// What this test verifies (guardian-schema.md §7):
//   - An RBACProfile that exceeds its governing RBACPolicy is rejected at admission
//   - An RBACProfile within policy bounds reaches provisioned=true
//   - provisioned=true is set exclusively by guardian (CS-INV-005)
//   - RBACProfile in a different tenant namespace than its targetCluster is rejected

import (
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("RBACProfile enforcement", func() {
	It("rejects RBACProfile that exceeds governing RBACPolicy permission scope", func() {
		Skip("lab cluster not yet provisioned")
	})

	It("sets provisioned=true when RBACProfile is within governing RBACPolicy bounds", func() {
		Skip("lab cluster not yet provisioned")
	})

	It("provisioned=true is written only by guardian, not by any other controller", func() {
		Skip("lab cluster not yet provisioned")
	})
})
