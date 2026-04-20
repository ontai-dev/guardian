package controller

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientevents "k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

// oidcDiscoveryPath is the well-known endpoint appended to an OIDC IssuerURL
// to verify reachability. RFC 8414 / OpenID Connect Discovery 1.0.
const oidcDiscoveryPath = "/.well-known/openid-configuration"

// oidcReachabilityTimeout is the HTTP timeout for OIDC discovery document fetches.
const oidcReachabilityTimeout = 10 * time.Second

// HTTPDoer is the interface satisfied by *http.Client and test doubles.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// IdentityProviderReconciler watches IdentityProvider CRs, validates their spec,
// checks OIDC provider reachability, and signals the EPGReconciler when the
// provider state changes.
//
// Reconcile loop:
//  1. Fetch IdentityProvider CR. Not found → no-op (INV-006).
//  2. Defer status patch.
//  3. Advance ObservedGeneration.
//  4. Call ValidateIdentityProviderSpec — pure structural validation.
//  5. If invalid: set Valid=False condition, emit Warning event, return.
//  6. Set Valid=True condition.
//  7. For Type=oidc: fetch discovery document, set Reachable condition.
//  8. Annotate with epg-recompute-requested to signal EPGReconciler.
//
// +kubebuilder:rbac:groups=security.ontai.dev,resources=identityproviders,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.ontai.dev,resources=identityproviders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.ontai.dev,resources=identityproviders/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
type IdentityProviderReconciler struct {
	// Client is the controller-runtime client for Kubernetes API access.
	Client client.Client

	// Scheme is the runtime scheme used for object type registration.
	Scheme *runtime.Scheme

	// Recorder is the Kubernetes event recorder for emitting Warning and Normal events.
	Recorder clientevents.EventRecorder

	// HTTPClient is used for OIDC discovery document reachability checks.
	// If nil, http.DefaultClient is used. Inject a test double in tests.
	HTTPClient HTTPDoer
}

// httpClient returns the configured HTTPDoer, defaulting to http.DefaultClient.
func (r *IdentityProviderReconciler) httpClient() HTTPDoer {
	if r.HTTPClient != nil {
		return r.HTTPClient
	}
	return &http.Client{Timeout: oidcReachabilityTimeout}
}

// Reconcile is the main reconciliation loop for IdentityProvider.
func (r *IdentityProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Step 1 — Fetch the IdentityProvider CR.
	// Not found means the CR was deleted. INV-006: no Jobs on the delete path.
	provider := &securityv1alpha1.IdentityProvider{}
	if err := r.Client.Get(ctx, req.NamespacedName, provider); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("IdentityProvider not found — likely deleted, ignoring",
				"namespacedName", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get IdentityProvider %s: %w", req.NamespacedName, err)
	}

	// Step 2 — Deferred status patch.
	patchBase := client.MergeFrom(provider.DeepCopy())
	defer func() {
		if err := r.Client.Status().Patch(ctx, provider, patchBase); err != nil {
			if !apierrors.IsNotFound(err) {
				logger.Error(err, "failed to patch IdentityProvider status",
					"name", provider.Name, "namespace", provider.Namespace)
			}
		}
	}()

	// Step 3 — Advance ObservedGeneration.
	provider.Status.ObservedGeneration = provider.Generation

	// Step 3a — Initialize LineageSynced on first observation.
	// One-time write only. The reconciler never updates this condition again.
	// InfrastructureLineageController takes ownership when deployed.
	// seam-core-schema.md §7 Declaration 5.
	if securityv1alpha1.FindCondition(provider.Status.Conditions, securityv1alpha1.ConditionTypeLineageSynced) == nil {
		securityv1alpha1.SetCondition(
			&provider.Status.Conditions,
			securityv1alpha1.ConditionTypeLineageSynced,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonLineageControllerAbsent,
			"InfrastructureLineageController is not yet deployed.",
			provider.Generation,
		)
	}

	// Step 4 — Structural validation.
	validationResult := ValidateIdentityProviderSpec(provider.Spec)
	if !validationResult.Valid {
		joinedReasons := strings.Join(validationResult.Reasons, "; ")

		securityv1alpha1.SetCondition(
			&provider.Status.Conditions,
			securityv1alpha1.ConditionTypeIdentityProviderValid,
			metav1.ConditionFalse,
			securityv1alpha1.ReasonIdentityProviderInvalid,
			joinedReasons,
			provider.Generation,
		)

		r.Recorder.Eventf(provider, nil, corev1.EventTypeWarning, "ValidationFailed", "ValidationFailed", joinedReasons)
		logger.Info("IdentityProvider validation failed",
			"name", provider.Name, "namespace", provider.Namespace, "reasons", joinedReasons)

		return ctrl.Result{}, nil
	}

	// Step 5 — Structural validation passed.
	securityv1alpha1.SetCondition(
		&provider.Status.Conditions,
		securityv1alpha1.ConditionTypeIdentityProviderValid,
		metav1.ConditionTrue,
		securityv1alpha1.ReasonIdentityProviderValid,
		"IdentityProvider spec is valid.",
		provider.Generation,
	)

	// Step 6 — OIDC reachability check.
	if provider.Spec.Type == securityv1alpha1.IdentityProviderTypeOIDC {
		discoveryURL := strings.TrimRight(provider.Spec.IssuerURL, "/") + oidcDiscoveryPath
		reachable, reason := r.checkOIDCReachability(ctx, discoveryURL)
		if reachable {
			securityv1alpha1.SetCondition(
				&provider.Status.Conditions,
				securityv1alpha1.ConditionTypeIdentityProviderReachable,
				metav1.ConditionTrue,
				securityv1alpha1.ReasonIdentityProviderReachable,
				"OIDC discovery document fetched successfully.",
				provider.Generation,
			)
		} else {
			securityv1alpha1.SetCondition(
				&provider.Status.Conditions,
				securityv1alpha1.ConditionTypeIdentityProviderReachable,
				metav1.ConditionFalse,
				securityv1alpha1.ReasonIdentityProviderUnreachable,
				reason,
				provider.Generation,
			)
			r.Recorder.Eventf(provider, nil, corev1.EventTypeWarning, "Unreachable", "Unreachable", reason)
			logger.Info("IdentityProvider OIDC issuer unreachable",
				"name", provider.Name, "issuerURL", provider.Spec.IssuerURL, "reason", reason)
		}
	}

	r.Recorder.Eventf(provider, nil, corev1.EventTypeNormal, "Validated", "Validated",
		"IdentityProvider validated successfully.")
	logger.Info("IdentityProvider validated",
		"name", provider.Name, "namespace", provider.Namespace, "type", provider.Spec.Type)

	// Step 7 — Signal EPGReconciler. IdentityProvider changes affect which
	// IdentityBindings are valid for this provider type, which affects EPG inputs.
	epgBase := provider.DeepCopy()
	epgTarget := provider.DeepCopy()
	if epgTarget.Annotations == nil {
		epgTarget.Annotations = make(map[string]string)
	}
	epgTarget.Annotations[epgRecomputeAnnotation] = "true"
	if err := r.Client.Patch(ctx, epgTarget, client.MergeFrom(epgBase)); err != nil {
		if !apierrors.IsNotFound(err) {
			logger.Error(err, "failed to annotate IdentityProvider with epg-recompute-requested",
				"name", provider.Name, "namespace", provider.Namespace)
		}
	}

	return ctrl.Result{}, nil
}

// checkOIDCReachability attempts to GET the OIDC discovery document at discoveryURL.
// Returns (true, "") on HTTP 200; (false, reason) otherwise.
func (r *IdentityProviderReconciler) checkOIDCReachability(ctx context.Context, discoveryURL string) (bool, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return false, fmt.Sprintf("failed to build request for %s: %v", discoveryURL, err)
	}

	resp, err := r.httpClient().Do(req)
	if err != nil {
		return false, fmt.Sprintf("GET %s failed: %v", discoveryURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("GET %s returned HTTP %d", discoveryURL, resp.StatusCode)
	}

	return true, ""
}

// SetupWithManager registers IdentityProviderReconciler as the controller for IdentityProvider.
func (r *IdentityProviderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.IdentityProvider{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
