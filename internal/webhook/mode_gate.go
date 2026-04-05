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

// NamespaceEnforcementRegistry records which namespaces have transitioned to full
// RBAC enforcement. Entries are written by BootstrapController and read by
// GuardedNamespaceModeResolver on each admission request.
//
// All methods are safe for concurrent use. Entries are never deleted — the
// enforcement transition is one-way and irreversible.
type NamespaceEnforcementRegistry struct {
	mu     sync.RWMutex
	active map[string]struct{}
}

// NewNamespaceEnforcementRegistry returns an empty registry with no active enforcements.
func NewNamespaceEnforcementRegistry() *NamespaceEnforcementRegistry {
	return &NamespaceEnforcementRegistry{
		active: make(map[string]struct{}),
	}
}

// IsActive reports whether namespace ns has been promoted to full enforcement.
// Safe for concurrent use.
func (r *NamespaceEnforcementRegistry) IsActive(ns string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.active[ns]
	return ok
}

// SetActive marks namespace ns as promoted to full enforcement. Idempotent.
// Safe for concurrent use. The promotion is permanent — there is no RemoveActive.
func (r *NamespaceEnforcementRegistry) SetActive(ns string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active[ns] = struct{}{}
}
