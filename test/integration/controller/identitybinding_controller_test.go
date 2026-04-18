package controller_test

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

const ibTestNamespace = "default"

// TestIdentityBindingReconciler_ValidOIDCNoProvider verifies that a valid OIDC
// IdentityBinding without IdentityProviderRef reaches Valid=True without trust check.
func TestIdentityBindingReconciler_ValidOIDCNoProvider(t *testing.T) {
	ctx := context.Background()
	name := "test-ib-oidc-noprovider"

	binding := &securityv1alpha1.IdentityBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ibTestNamespace,
		},
		Spec: securityv1alpha1.IdentityBindingSpec{
			IdentityType:  securityv1alpha1.IdentityTypeOIDC,
			PrincipalName: "oidc-user",
			TrustMethod:   securityv1alpha1.TrustMethodMTLS,
			OIDCConfig: &securityv1alpha1.OIDCConfig{
				Issuer:   "https://accounts.example.com",
				ClientID: "test-client",
			},
		},
	}
	if err := k8sClient.Create(ctx, binding); err != nil {
		t.Fatalf("failed to create IdentityBinding: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, binding) })

	ok := poll(t, 10*time.Second, func() bool {
		var b securityv1alpha1.IdentityBinding
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ibTestNamespace}, &b); err != nil {
			return false
		}
		c := securityv1alpha1.FindCondition(b.Status.Conditions, securityv1alpha1.ConditionTypeIdentityBindingValid)
		return c != nil && c.Status == metav1.ConditionTrue
	})
	if !ok {
		var b securityv1alpha1.IdentityBinding
		_ = k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ibTestNamespace}, &b)
		t.Errorf("IdentityBinding did not reach Valid=True; conditions: %+v", b.Status.Conditions)
	}
}

// TestIdentityBindingReconciler_InvalidSpec verifies that an IdentityBinding with
// missing required fields reaches Valid=False.
func TestIdentityBindingReconciler_InvalidSpec(t *testing.T) {
	ctx := context.Background()
	name := "test-ib-invalid-spec"

	binding := &securityv1alpha1.IdentityBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ibTestNamespace,
		},
		Spec: securityv1alpha1.IdentityBindingSpec{
			IdentityType:  securityv1alpha1.IdentityTypeOIDC,
			PrincipalName: "", // invalid: empty
			TrustMethod:   securityv1alpha1.TrustMethodMTLS,
			OIDCConfig: &securityv1alpha1.OIDCConfig{
				Issuer:   "https://accounts.example.com",
				ClientID: "test-client",
			},
		},
	}
	if err := k8sClient.Create(ctx, binding); err != nil {
		t.Fatalf("failed to create IdentityBinding: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, binding) })

	ok := poll(t, 10*time.Second, func() bool {
		var b securityv1alpha1.IdentityBinding
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ibTestNamespace}, &b); err != nil {
			return false
		}
		c := securityv1alpha1.FindCondition(b.Status.Conditions, securityv1alpha1.ConditionTypeIdentityBindingValid)
		return c != nil && c.Status == metav1.ConditionFalse
	})
	if !ok {
		var b securityv1alpha1.IdentityBinding
		_ = k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ibTestNamespace}, &b)
		t.Errorf("IdentityBinding did not reach Valid=False; conditions: %+v", b.Status.Conditions)
	}
}

// TestIdentityBindingReconciler_WithValidProvider verifies that an IdentityBinding
// with IdentityProviderRef set and a valid matching IdentityProvider reaches
// TrustAnchorResolved=True and Valid=True.
func TestIdentityBindingReconciler_WithValidProvider(t *testing.T) {
	ctx := context.Background()
	providerName := "test-oidc-provider-trust"
	bindingName := "test-ib-with-provider"

	// Create the IdentityProvider first.
	provider := &securityv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      providerName,
			Namespace: ibTestNamespace,
		},
		Spec: securityv1alpha1.IdentityProviderSpec{
			Type:      securityv1alpha1.IdentityProviderTypeOIDC,
			IssuerURL: "https://accounts.example.com",
		},
	}
	if err := k8sClient.Create(ctx, provider); err != nil {
		t.Fatalf("failed to create IdentityProvider: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, provider) })

	// Wait for IdentityProvider to reach Valid=True (IdentityProviderReconciler runs).
	okProvider := poll(t, 10*time.Second, func() bool {
		var p securityv1alpha1.IdentityProvider
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: providerName, Namespace: ibTestNamespace}, &p); err != nil {
			return false
		}
		c := securityv1alpha1.FindCondition(p.Status.Conditions, securityv1alpha1.ConditionTypeIdentityProviderValid)
		return c != nil && c.Status == metav1.ConditionTrue
	})
	if !okProvider {
		t.Fatal("IdentityProvider did not reach Valid=True within timeout")
	}

	// Now create the IdentityBinding referencing the provider.
	binding := &securityv1alpha1.IdentityBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: ibTestNamespace,
		},
		Spec: securityv1alpha1.IdentityBindingSpec{
			IdentityType:        securityv1alpha1.IdentityTypeOIDC,
			PrincipalName:       "oidc-principal",
			TrustMethod:         securityv1alpha1.TrustMethodMTLS,
			IdentityProviderRef: providerName,
			OIDCConfig: &securityv1alpha1.OIDCConfig{
				Issuer:   "https://accounts.example.com",
				ClientID: "test-client",
			},
		},
	}
	if err := k8sClient.Create(ctx, binding); err != nil {
		t.Fatalf("failed to create IdentityBinding: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, binding) })

	okBinding := poll(t, 10*time.Second, func() bool {
		var b securityv1alpha1.IdentityBinding
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: bindingName, Namespace: ibTestNamespace}, &b); err != nil {
			return false
		}
		valid := securityv1alpha1.FindCondition(b.Status.Conditions, securityv1alpha1.ConditionTypeIdentityBindingValid)
		trust := securityv1alpha1.FindCondition(b.Status.Conditions, securityv1alpha1.ConditionTypeIdentityBindingTrustAnchorResolved)
		return valid != nil && valid.Status == metav1.ConditionTrue &&
			trust != nil && trust.Status == metav1.ConditionTrue
	})
	if !okBinding {
		var b securityv1alpha1.IdentityBinding
		_ = k8sClient.Get(ctx, types.NamespacedName{Name: bindingName, Namespace: ibTestNamespace}, &b)
		t.Errorf("IdentityBinding did not reach Valid=True + TrustAnchorResolved=True; conditions: %+v", b.Status.Conditions)
	}
}

// TestIdentityBindingReconciler_MissingProvider verifies that an IdentityBinding
// with IdentityProviderRef pointing to a non-existent provider reaches
// TrustAnchorResolved=False and Valid=False.
func TestIdentityBindingReconciler_MissingProvider(t *testing.T) {
	ctx := context.Background()
	bindingName := "test-ib-missing-provider"

	binding := &securityv1alpha1.IdentityBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: ibTestNamespace,
		},
		Spec: securityv1alpha1.IdentityBindingSpec{
			IdentityType:        securityv1alpha1.IdentityTypeOIDC,
			PrincipalName:       "oidc-principal",
			TrustMethod:         securityv1alpha1.TrustMethodMTLS,
			IdentityProviderRef: "does-not-exist",
			OIDCConfig: &securityv1alpha1.OIDCConfig{
				Issuer:   "https://accounts.example.com",
				ClientID: "test-client",
			},
		},
	}
	if err := k8sClient.Create(ctx, binding); err != nil {
		t.Fatalf("failed to create IdentityBinding: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, binding) })

	ok := poll(t, 10*time.Second, func() bool {
		var b securityv1alpha1.IdentityBinding
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: bindingName, Namespace: ibTestNamespace}, &b); err != nil {
			return false
		}
		valid := securityv1alpha1.FindCondition(b.Status.Conditions, securityv1alpha1.ConditionTypeIdentityBindingValid)
		trust := securityv1alpha1.FindCondition(b.Status.Conditions, securityv1alpha1.ConditionTypeIdentityBindingTrustAnchorResolved)
		return valid != nil && valid.Status == metav1.ConditionFalse &&
			trust != nil && trust.Status == metav1.ConditionFalse
	})
	if !ok {
		var b securityv1alpha1.IdentityBinding
		_ = k8sClient.Get(ctx, types.NamespacedName{Name: bindingName, Namespace: ibTestNamespace}, &b)
		t.Errorf("IdentityBinding did not reach Valid=False + TrustAnchorResolved=False; conditions: %+v", b.Status.Conditions)
	}
}

// TestIdentityBindingReconciler_TypeMismatch verifies that an IdentityBinding
// referencing an IdentityProvider with a mismatched type reaches
// TrustAnchorResolved=False with TrustAnchorTypeMismatch reason.
func TestIdentityBindingReconciler_TypeMismatch(t *testing.T) {
	ctx := context.Background()
	providerName := "test-pki-provider-mismatch"
	bindingName := "test-ib-type-mismatch"

	// Create a PKI provider.
	provider := &securityv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      providerName,
			Namespace: ibTestNamespace,
		},
		Spec: securityv1alpha1.IdentityProviderSpec{
			Type:     securityv1alpha1.IdentityProviderTypePKI,
			CABundle: "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----",
		},
	}
	if err := k8sClient.Create(ctx, provider); err != nil {
		t.Fatalf("failed to create IdentityProvider: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, provider) })

	// Wait for provider to be valid.
	_ = poll(t, 10*time.Second, func() bool {
		var p securityv1alpha1.IdentityProvider
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: providerName, Namespace: ibTestNamespace}, &p); err != nil {
			return false
		}
		c := securityv1alpha1.FindCondition(p.Status.Conditions, securityv1alpha1.ConditionTypeIdentityProviderValid)
		return c != nil && c.Status == metav1.ConditionTrue
	})

	// Create an OIDC binding referencing the PKI provider (type mismatch).
	binding := &securityv1alpha1.IdentityBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: ibTestNamespace,
		},
		Spec: securityv1alpha1.IdentityBindingSpec{
			IdentityType:        securityv1alpha1.IdentityTypeOIDC, // expects oidc provider
			PrincipalName:       "oidc-principal",
			TrustMethod:         securityv1alpha1.TrustMethodMTLS,
			IdentityProviderRef: providerName, // pki provider — mismatch
			OIDCConfig: &securityv1alpha1.OIDCConfig{
				Issuer:   "https://accounts.example.com",
				ClientID: "test-client",
			},
		},
	}
	if err := k8sClient.Create(ctx, binding); err != nil {
		t.Fatalf("failed to create IdentityBinding: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, binding) })

	ok := poll(t, 10*time.Second, func() bool {
		var b securityv1alpha1.IdentityBinding
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: bindingName, Namespace: ibTestNamespace}, &b); err != nil {
			return false
		}
		trust := securityv1alpha1.FindCondition(b.Status.Conditions, securityv1alpha1.ConditionTypeIdentityBindingTrustAnchorResolved)
		return trust != nil && trust.Status == metav1.ConditionFalse &&
			trust.Reason == securityv1alpha1.ReasonTrustAnchorTypeMismatch
	})
	if !ok {
		var b securityv1alpha1.IdentityBinding
		_ = k8sClient.Get(ctx, types.NamespacedName{Name: bindingName, Namespace: ibTestNamespace}, &b)
		t.Errorf("IdentityBinding did not reach TrustAnchorTypeMismatch; conditions: %+v", b.Status.Conditions)
	}

}
