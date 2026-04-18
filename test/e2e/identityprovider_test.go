package e2e_test

// Scenario: IdentityProvider trust resolution
//
// Pre-conditions required for this test to run:
//   - ccs-mgmt fully provisioned (MGMT_KUBECONFIG set)
//   - guardian running in seam-system; webhook in Enforce mode
//   - An IdentityProvider CR exists in security-system declaring the upstream
//     trust anchor (e.g. a PKI CA or OIDC issuer endpoint reachable from ccs-mgmt)
//
// What this test verifies (guardian-schema.md §7):
//   - IdentityBinding without a matching IdentityProvider for its identityType
//     is rejected at admission
//   - IdentityBinding with a matching IdentityProvider is admitted and reaches
//     Bound status
//   - Guardian validates IdentityBinding trust assertions against the declared
//     IdentityProvider

import (
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("IdentityProvider trust resolution", func() {
	It("rejects IdentityBinding when no matching IdentityProvider exists for the identityType", func() {
		Skip("lab cluster not yet provisioned")
	})

	It("admits IdentityBinding when a matching IdentityProvider is present", func() {
		Skip("lab cluster not yet provisioned")
	})

	It("IdentityBinding reaches Bound status after guardian validates trust assertions", func() {
		Skip("lab cluster not yet provisioned")
	})
})
