package webhook

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// WebhookModeLabelKey is the namespace label key that controls per-namespace
// admission enforcement tier. The label is stamped by `compiler enable` on
// seam-system and kube-system before Guardian is deployed. INV-020, CS-INV-004.
const WebhookModeLabelKey = "seam.ontai.dev/webhook-mode"

// NamespaceMode is the per-namespace admission enforcement tier.
// The tier is determined by the namespace's WebhookModeLabelKey label value.
// Unlabelled namespaces default to Enforce — unknown namespaces are governed,
// not exempted.
type NamespaceMode string

const (
	// NamespaceModeExempt causes the webhook to skip all admission decisions
	// for resources in this namespace. Applied permanently to seam-system and
	// kube-system by compiler enable before Guardian is deployed. CS-INV-004.
	NamespaceModeExempt NamespaceMode = "exempt"

	// NamespaceModeObserve causes the webhook to run full policy evaluation and
	// record the decision, but always return allowed. Used for bootstrap trust
	// namespaces during initial cluster formation.
	NamespaceModeObserve NamespaceMode = "observe"

	// NamespaceModeEnforce causes the webhook to apply full deny posture.
	// This is the default for all namespaces carrying no WebhookModeLabelKey label
	// (unknown namespaces are governed, not exempted).
	NamespaceModeEnforce NamespaceMode = "enforce"
)

// NamespaceModeResolver resolves the effective admission enforcement tier for a
// given namespace. Implementations may consult namespace labels, global mode gates,
// or per-namespace enforcement registries.
type NamespaceModeResolver interface {
	// ResolveMode returns the effective NamespaceMode for the given namespace.
	// An empty namespace (cluster-scoped resources) returns NamespaceModeEnforce.
	ResolveMode(ctx context.Context, namespace string) NamespaceMode
}

// KubeNamespaceModeResolver resolves NamespaceMode by reading the
// WebhookModeLabelKey label from the Kubernetes Namespace object.
//
// Fail-safe semantics: if the namespace cannot be read (API error, not found,
// or empty namespace for cluster-scoped resources), the resolver returns
// NamespaceModeEnforce. Unknown namespaces are governed, not exempted.
type KubeNamespaceModeResolver struct {
	Client client.Client
}

// ResolveMode reads the namespace's WebhookModeLabelKey label and maps it to the
// corresponding NamespaceMode. An empty namespace (cluster-scoped resources) or
// any read error returns NamespaceModeEnforce.
func (r *KubeNamespaceModeResolver) ResolveMode(ctx context.Context, namespace string) NamespaceMode {
	if namespace == "" {
		// Cluster-scoped resources (ClusterRole, ClusterRoleBinding) have no namespace.
		// Default to enforce: governance applies to cluster-scoped RBAC.
		return NamespaceModeEnforce
	}

	ns := &corev1.Namespace{}
	if err := r.Client.Get(ctx, types.NamespacedName{Name: namespace}, ns); err != nil {
		if apierrors.IsNotFound(err) {
			// Namespace does not exist — enforce. Unknown = governed.
			return NamespaceModeEnforce
		}
		// API error — fail safe to enforce.
		return NamespaceModeEnforce
	}

	label := ns.Labels[WebhookModeLabelKey]
	switch NamespaceMode(label) {
	case NamespaceModeExempt:
		return NamespaceModeExempt
	case NamespaceModeObserve:
		return NamespaceModeObserve
	default:
		// Unlabelled or unrecognised value → enforce.
		return NamespaceModeEnforce
	}
}

// StaticNamespaceModeResolver resolves NamespaceMode from a pre-populated map.
// Used in unit tests and in cases where the mode mapping is statically known.
type StaticNamespaceModeResolver struct {
	// Modes maps namespace name to NamespaceMode. Missing entries resolve to
	// DefaultMode (which itself defaults to NamespaceModeEnforce if zero).
	Modes map[string]NamespaceMode
	// DefaultMode is returned for namespaces absent from the Modes map.
	// If unset, defaults to NamespaceModeEnforce.
	DefaultMode NamespaceMode
}

// ResolveMode returns the mode for the namespace from the static map, or
// DefaultMode (defaulting to NamespaceModeEnforce) if absent.
func (r *StaticNamespaceModeResolver) ResolveMode(_ context.Context, namespace string) NamespaceMode {
	if mode, ok := r.Modes[namespace]; ok {
		return mode
	}
	if r.DefaultMode != "" {
		return r.DefaultMode
	}
	return NamespaceModeEnforce
}
