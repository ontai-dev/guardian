package webhook

import (
	"sync"
	"sync/atomic"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

// WebhookModeGate is an in-memory atomic gate that tracks the current global
// admission enforcement mode. The gate is updated by BootstrapController when
// it detects transitions in the Guardian CR status. The webhook handler reads
// the gate on each incoming request via GuardedNamespaceModeResolver.
//
// The mode is a one-way ratchet: Initialising → ObserveOnly. There is no
// programmatic path back to Initialising once ObserveOnly is set.
// INV-020, CS-INV-004.
type WebhookModeGate struct {
	mode atomic.Value // stores securityv1alpha1.WebhookMode
}

// NewWebhookModeGate returns a WebhookModeGate in the Initialising state.
// The BootstrapController advances it to ObserveOnly when bootstrap RBACProfiles
// are all provisioned. INV-020.
func NewWebhookModeGate() *WebhookModeGate {
	g := &WebhookModeGate{}
	g.mode.Store(securityv1alpha1.WebhookModeInitialising)
	return g
}

// Mode returns the current WebhookMode. Safe for concurrent use.
func (g *WebhookModeGate) Mode() securityv1alpha1.WebhookMode {
	return g.mode.Load().(securityv1alpha1.WebhookMode)
}

// SetMode updates the mode to m. SetMode is idempotent and safe for concurrent use.
// It does not enforce the one-way ratchet — callers (BootstrapController) are
// responsible for only advancing the mode forward. INV-020.
func (g *WebhookModeGate) SetMode(m securityv1alpha1.WebhookMode) {
	g.mode.Store(m)
}

// NamespaceEnforcementRegistry records namespace enforcement progression.
//
// There are two tiers of per-namespace promotion, each one-way and irreversible:
//
//  1. Active — all RBACProfiles in the namespace are Provisioned=True.
//     Set by BootstrapController when ObserveOnly readiness is reached.
//     Used as a prerequisite gate for Enforcing promotion.
//
//  2. Enforcing — all RBACProfiles are provisioned AND all RBAC resources in
//     the namespace carry ontai.dev/rbac-owner=guardian.
//     Set by BootstrapController when the per-namespace Enforcing check passes.
//     The webhook handler uses IsEnforcing to decide whether to reject or observe.
//
// All methods are safe for concurrent use. Entries are never deleted.
type NamespaceEnforcementRegistry struct {
	mu        sync.RWMutex
	active    map[string]struct{}
	enforcing map[string]struct{}
}

// NewNamespaceEnforcementRegistry returns an empty registry with no active enforcements.
func NewNamespaceEnforcementRegistry() *NamespaceEnforcementRegistry {
	return &NamespaceEnforcementRegistry{
		active:    make(map[string]struct{}),
		enforcing: make(map[string]struct{}),
	}
}

// IsActive reports whether namespace ns has reached the Active tier
// (all RBACProfiles provisioned). Safe for concurrent use.
func (r *NamespaceEnforcementRegistry) IsActive(ns string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.active[ns]
	return ok
}

// SetActive marks namespace ns as Active (all RBACProfiles provisioned). Idempotent.
// Safe for concurrent use. The promotion is permanent — there is no RemoveActive.
func (r *NamespaceEnforcementRegistry) SetActive(ns string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active[ns] = struct{}{}
}

// IsEnforcing reports whether namespace ns has reached the Enforcing tier
// (all RBACProfiles provisioned AND all RBAC resources annotated with
// ontai.dev/rbac-owner=guardian). The webhook handler uses this to decide
// whether to reject (enforcing) or observe (not yet enforcing). Safe for concurrent use.
func (r *NamespaceEnforcementRegistry) IsEnforcing(ns string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.enforcing[ns]
	return ok
}

// SetEnforcing marks namespace ns as Enforcing (all RBACProfiles provisioned AND
// all RBAC resources annotated). Idempotent. Safe for concurrent use.
// The promotion is permanent — there is no RemoveEnforcing. INV-020.
func (r *NamespaceEnforcementRegistry) SetEnforcing(ns string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enforcing[ns] = struct{}{}
}
