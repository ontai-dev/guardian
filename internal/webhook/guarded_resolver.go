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
//  3. If global mode is ObserveOnly or Enforcing: check the per-namespace registry.
//     If the namespace is active in the registry: return the base resolver's mode
//     (which at this point is Enforce or Observe from namespace labels).
//     If the namespace is not yet in the registry: return Observe.
//
// This ensures:
//   - Exempt namespaces (seam-system, kube-system) are always exempt.
//   - During bootstrap (Initialising): all non-exempt namespaces observe.
//   - After ObserveOnly: namespaces promoted by BootstrapController enforce;
//     namespaces not yet promoted continue to observe.
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

	// Gate 3: ObserveOnly or Enforcing global state — check per-namespace registry.
	// Namespaces promoted by BootstrapController return their base mode (Enforce or
	// Observe from label). Namespaces not yet promoted default to Observe.
	if r.registry.IsActive(namespace) {
		return baseMode
	}
	return NamespaceModeObserve
}
