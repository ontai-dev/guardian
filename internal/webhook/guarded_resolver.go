package webhook

import (
	"context"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

// GuardedNamespaceModeResolver wraps a base NamespaceModeResolver with a global
// WebhookModeGate and a NamespaceEnforcementRegistry to implement the bootstrap
// observe-only startup and per-namespace enforce transition.
//
// Resolution order:
//  1. Delegate to base resolver first. If base returns Exempt: return Exempt
//     immediately — exempt namespaces are never overridden by the global gate.
//  2. If global mode is Initialising: return Observe — no denials while guardian
//     is bootstrapping. The bootstrap window is still open. INV-020.
//  3. If global mode is ObserveOnly or Enforcing: check the per-namespace enforcing
//     registry (IsEnforcing). If the namespace has been promoted to Enforcing:
//     return the base resolver's mode (Enforce for unlabelled namespaces → actual
//     denials are issued). If the namespace is Active but not yet Enforcing, or not
//     yet Active at all: return Observe (log would-deny, admit unconditionally).
//
// This ensures:
//   - Exempt namespaces (seam-system, kube-system) are always exempt.
//   - During bootstrap (Initialising): all non-exempt namespaces observe.
//   - After ObserveOnly: namespaces promoted to Enforcing by BootstrapController
//     apply full deny posture; all other namespaces continue to observe.
//   - The Enforcing tier requires both profile provisioning (Active) AND full
//     RBAC annotation coverage (Enforcing), preventing premature denials.
type GuardedNamespaceModeResolver struct {
	base     NamespaceModeResolver
	gate     *WebhookModeGate
	registry *NamespaceEnforcementRegistry
}

// NewGuardedNamespaceModeResolver constructs a GuardedNamespaceModeResolver.
// base is the underlying resolver (KubeNamespaceModeResolver in production).
// gate is the in-memory global mode gate updated by BootstrapController.
// registry is the in-memory per-namespace enforcement registry.
func NewGuardedNamespaceModeResolver(
	base NamespaceModeResolver,
	gate *WebhookModeGate,
	registry *NamespaceEnforcementRegistry,
) *GuardedNamespaceModeResolver {
	return &GuardedNamespaceModeResolver{
		base:     base,
		gate:     gate,
		registry: registry,
	}
}

// ResolveMode implements NamespaceModeResolver.
func (r *GuardedNamespaceModeResolver) ResolveMode(ctx context.Context, namespace string) NamespaceMode {
	baseMode := r.base.ResolveMode(ctx, namespace)

	// Gate 1: exempt namespaces bypass the global gate entirely.
	if baseMode == NamespaceModeExempt {
		return NamespaceModeExempt
	}

	globalMode := r.gate.Mode()

	// Gate 2: during bootstrap (Initialising), all non-exempt namespaces observe.
	// No denials are issued until BootstrapController advances the gate. INV-020.
	if globalMode == securityv1alpha1.WebhookModeInitialising {
		return NamespaceModeObserve
	}

	// Gate 3: ObserveOnly or Enforcing global state — check the per-namespace enforcing
	// registry. Only namespaces that have been explicitly promoted to the Enforcing tier
	// by BootstrapController apply the base resolver's mode (deny posture for unlabelled
	// namespaces). All other namespaces — including those that are Active (profiles
	// provisioned) but not yet Enforcing (RBAC annotation coverage incomplete) — return
	// Observe. This ensures premature denials never fire before the annotation sweep
	// and enforcing readiness check have both confirmed the namespace is clean.
	if r.registry.IsEnforcing(namespace) {
		return baseMode
	}
	return NamespaceModeObserve
}
