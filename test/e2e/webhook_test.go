package e2e_test

// Scenario: Webhook enforce transition after bootstrap
//
// Pre-conditions required for this test to run:
//   - ccs-mgmt fully provisioned and reachable (MGMT_KUBECONFIG set)
//   - guardian operator running in seam-system on ccs-mgmt
//   - Guardian singleton CR exists (BootstrapController has run)
//   - seam-system namespace carries seam.ontai.dev/webhook-mode=exempt
//   - RBACProfile for guardian itself is provisioned (provisioned=true)
//   - No other operators running (isolates guardian webhook behaviour)
//
// What this test verifies (guardian-schema.md §4, session/34 WS2):
//   - Guardian starts in Initialising/ObserveOnly mode after CRD-only bootstrap
//   - Once all declared RBACProfiles reach provisioned=true, guardian transitions
//     to WebhookMode=Enforce globally
//   - After enforce transition, RBAC resources lacking ontai.dev/rbac-owner=guardian
//     are rejected at admission with a structured error
//   - Resources with the annotation are admitted

import (
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("webhook enforce transition after bootstrap", func() {
	It("guardian starts in ObserveOnly mode before RBACProfiles are provisioned", func() {
		Skip("lab cluster not yet provisioned")
	})

	It("guardian transitions to Enforce mode when all RBACProfiles reach provisioned=true", func() {
		Skip("lab cluster not yet provisioned")
	})

	It("rejects RBAC resource without ontai.dev/rbac-owner=guardian annotation after enforce", func() {
		Skip("lab cluster not yet provisioned")
	})

	It("admits RBAC resource with ontai.dev/rbac-owner=guardian annotation after enforce", func() {
		Skip("lab cluster not yet provisioned")
	})
})
