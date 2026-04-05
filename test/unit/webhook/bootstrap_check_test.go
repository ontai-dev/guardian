// Package webhook_test contains unit tests for CheckBootstrapLabels.
//
// Tests verify:
//   - Label present with correct value (exempt): CheckBootstrapLabels returns nil.
//   - Label absent: CheckBootstrapLabels returns ErrBootstrapLabelAbsent.
//   - Label present with wrong value (e.g., "enforce"): returns ErrBootstrapLabelAbsent.
//   - Namespace not found: returns a non-nil error (not ErrBootstrapLabelAbsent).
//
// WS3, INV-020, CS-INV-004.
package webhook_test

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/ontai-dev/guardian/internal/webhook"
)

func bootstrapCheckScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	return s
}

func seamSystemNamespace(labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "seam-system",
			Labels: labels,
		},
	}
}

// Test 35 — Exempt label present: CheckBootstrapLabels returns nil.
// The seam-system namespace carries seam.ontai.dev/webhook-mode=exempt — the
// label stamped by `compiler enable`. Guardian may proceed to register the webhook.
// WS3, INV-020, CS-INV-004.
func TestCheckBootstrapLabels_LabelPresent_ReturnsNil(t *testing.T) {
	s := bootstrapCheckScheme(t)
	ns := seamSystemNamespace(map[string]string{
		webhook.WebhookModeLabelKey: string(webhook.NamespaceModeExempt),
	})
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns).Build()

	err := webhook.CheckBootstrapLabels(context.Background(), c)
	if err != nil {
		t.Errorf("expected nil when label present; got %v", err)
	}
}

// Test 36 — Label absent: CheckBootstrapLabels returns ErrBootstrapLabelAbsent.
// seam-system has no labels — `compiler enable` has not been run.
// Guardian must refuse to register the webhook. WS3.
func TestCheckBootstrapLabels_LabelAbsent_ReturnsErrBootstrapLabelAbsent(t *testing.T) {
	s := bootstrapCheckScheme(t)
	ns := seamSystemNamespace(nil) // no labels
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns).Build()

	err := webhook.CheckBootstrapLabels(context.Background(), c)
	if !errors.Is(err, webhook.ErrBootstrapLabelAbsent) {
		t.Errorf("expected ErrBootstrapLabelAbsent; got %v", err)
	}
}

// Test 37 — Label present but wrong value: CheckBootstrapLabels returns ErrBootstrapLabelAbsent.
// The label key exists but with a non-exempt value (e.g., "enforce"). The label must
// be exactly "exempt" — any other value is treated as absent. WS3.
func TestCheckBootstrapLabels_WrongLabelValue_ReturnsErrBootstrapLabelAbsent(t *testing.T) {
	s := bootstrapCheckScheme(t)
	ns := seamSystemNamespace(map[string]string{
		webhook.WebhookModeLabelKey: string(webhook.NamespaceModeEnforce),
	})
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns).Build()

	err := webhook.CheckBootstrapLabels(context.Background(), c)
	if !errors.Is(err, webhook.ErrBootstrapLabelAbsent) {
		t.Errorf("expected ErrBootstrapLabelAbsent for wrong value; got %v", err)
	}
}

// Test 38 — Namespace not found: CheckBootstrapLabels returns a non-nil error.
// If the seam-system namespace itself is absent, something is fundamentally wrong.
// The returned error must not be ErrBootstrapLabelAbsent — it is an API error.
func TestCheckBootstrapLabels_NamespaceNotFound_ReturnsError(t *testing.T) {
	s := bootstrapCheckScheme(t)
	// No seam-system namespace in the fake client.
	c := fake.NewClientBuilder().WithScheme(s).Build()

	err := webhook.CheckBootstrapLabels(context.Background(), c)
	if err == nil {
		t.Error("expected non-nil error when seam-system namespace absent; got nil")
	}
	if errors.Is(err, webhook.ErrBootstrapLabelAbsent) {
		t.Errorf("expected API error (not ErrBootstrapLabelAbsent) when namespace absent; got %v", err)
	}
}

// Test 39 — Observe label value (non-exempt): CheckBootstrapLabels returns ErrBootstrapLabelAbsent.
// Only the "exempt" value is accepted. "observe" is not sufficient for the bootstrap label
// check — the exempt label is the specific gate. WS3.
func TestCheckBootstrapLabels_ObserveLabelValue_ReturnsErrBootstrapLabelAbsent(t *testing.T) {
	s := bootstrapCheckScheme(t)
	ns := seamSystemNamespace(map[string]string{
		webhook.WebhookModeLabelKey: string(webhook.NamespaceModeObserve),
	})
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns).Build()

	err := webhook.CheckBootstrapLabels(context.Background(), c)
	if !errors.Is(err, webhook.ErrBootstrapLabelAbsent) {
		t.Errorf("expected ErrBootstrapLabelAbsent for observe value; got %v", err)
	}
}
