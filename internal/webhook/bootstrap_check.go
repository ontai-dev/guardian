package webhook

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ErrBootstrapLabelAbsent is returned by CheckBootstrapLabels when the
// seam-system namespace is missing the seam.ontai.dev/webhook-mode=exempt label.
// Guardian refuses to register its admission webhook until this label is present.
// The label is stamped by `compiler enable` before guardian is deployed. WS3.
var ErrBootstrapLabelAbsent = fmt.Errorf(
	"namespace seam-system is missing label %s=%s; "+
		"run `compiler enable` to stamp bootstrap labels before starting guardian",
	WebhookModeLabelKey, NamespaceModeExempt,
)

// CheckBootstrapLabels verifies that the seam-system namespace carries the
// seam.ontai.dev/webhook-mode=exempt label that is stamped by `compiler enable`.
//
// Guardian refuses to register its admission webhook if this label is absent.
// The label signals that the bootstrap phase has completed and the cluster is
// ready for webhook-controlled admission. WS3, INV-020, CS-INV-004.
//
// Returns nil when the label is present with the correct value.
// Returns ErrBootstrapLabelAbsent when the label is absent or has a non-exempt value.
// Returns other errors on API read failure.
func CheckBootstrapLabels(ctx context.Context, c client.Client) error {
	ns := &corev1.Namespace{}
	if err := c.Get(ctx, types.NamespacedName{Name: "seam-system"}, ns); err != nil {
		return fmt.Errorf("failed to read seam-system namespace: %w", err)
	}

	if NamespaceMode(ns.Labels[WebhookModeLabelKey]) == NamespaceModeExempt {
		return nil
	}
	return ErrBootstrapLabelAbsent
}
