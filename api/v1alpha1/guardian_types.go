package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WebhookMode is the global admission enforcement mode of the guardian operator.
// It is a one-way ratchet: Initialising → ObserveOnly. Individual namespaces
// transition to full enforce independently via NamespaceEnforcements.
// INV-020, CS-INV-004.
type WebhookMode string

const (
	// WebhookModeInitialising is the mode set on guardian startup.
	// The webhook refuses to register until the bootstrap label check passes
	// (WS3). While in this mode, the global enforcement gate treats all
	// non-exempt namespaces as observe — no denials are issued.
	WebhookModeInitialising WebhookMode = "Initialising"

	// WebhookModeObserveOnly is set by BootstrapController when all
	// platform-native RBACProfiles from the compiler enable bundle have
	// reached Provisioned=True. In this mode the global gate allows
	// per-namespace transitions to enforce, tracked in NamespaceEnforcements.
	WebhookModeObserveOnly WebhookMode = "ObserveOnly"

	// WebhookModeEnforcing is informational: set when every known namespace
	// has an entry in NamespaceEnforcements. The per-namespace registry is the
	// canonical enforcement record; this field signals full-cluster readiness.
	WebhookModeEnforcing WebhookMode = "Enforcing"
)

// Condition type constants for Guardian CR.
const (
	// ConditionTypeBootstrapLabelAbsent is True when the seam-system namespace
	// is missing the seam.ontai.dev/webhook-mode=exempt label on startup.
	// Guardian refuses to register its admission webhook while this is True. WS3.
	ConditionTypeBootstrapLabelAbsent = "BootstrapLabelAbsent"

	// ConditionTypeWebhookRegistered is True when the admission webhook has been
	// successfully registered with the manager. INV-020.
	ConditionTypeWebhookRegistered = "WebhookRegistered"
)

// Condition reason constants for Guardian CR.
const (
	// ReasonLabelAbsent is the reason for ConditionTypeBootstrapLabelAbsent=True.
	ReasonLabelAbsent = "LabelAbsent"

	// ReasonLabelPresent is the reason for ConditionTypeBootstrapLabelAbsent=False.
	ReasonLabelPresent = "LabelPresent"

	// ReasonWebhookRegistered is the reason for ConditionTypeWebhookRegistered=True.
	ReasonWebhookRegistered = "WebhookRegistered"

	// ReasonBootstrapProfilesReady is the reason when WebhookMode advances to ObserveOnly.
	ReasonBootstrapProfilesReady = "BootstrapProfilesReady"

	// ReasonBootstrapProfilesPending is the reason when RBACProfiles are not yet all provisioned.
	ReasonBootstrapProfilesPending = "BootstrapProfilesPending"
)

// GuardianSpec has no user-configurable fields. Guardian is a status-only singleton
// CR that records the operator's own admission enforcement state.
type GuardianSpec struct{}

// GuardianStatus defines the observed admission enforcement state of the guardian
// operator. All fields are written exclusively by guardian controllers.
type GuardianStatus struct {
	// WebhookMode is the current global admission enforcement mode.
	// Transitions: Initialising → ObserveOnly (when bootstrap RBACProfiles provisioned).
	// ObserveOnly is the stable global mode; per-namespace enforce transitions are
	// tracked in NamespaceEnforcements. INV-020, CS-INV-004.
	// +optional
	WebhookMode WebhookMode `json:"webhookMode,omitempty"`

	// NamespaceEnforcements records the set of namespaces that have transitioned to
	// full RBAC enforcement. Populated by BootstrapController when all RBACProfiles
	// in a namespace reach Provisioned=True. This transition is one-way and irreversible.
	// Keys are namespace names; values are always true (absent key = not yet enforcing).
	// +optional
	NamespaceEnforcements map[string]bool `json:"namespaceEnforcements,omitempty"`

	// Conditions holds standard Kubernetes status conditions for Guardian.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Guardian is the singleton status CR for the guardian operator.
// It records the global webhook enforcement mode and per-namespace enforcement
// transitions managed by the BootstrapController.
//
// There is exactly one Guardian CR per cluster, named "guardian" in seam-system.
// It is created by guardian on startup if absent.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=gdn
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.status.webhookMode`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type Guardian struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GuardianSpec   `json:"spec,omitempty"`
	Status GuardianStatus `json:"status,omitempty"`
}

// GuardianList is the list type for Guardian.
//
// +kubebuilder:object:root=true
type GuardianList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Guardian `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Guardian{}, &GuardianList{})
}
