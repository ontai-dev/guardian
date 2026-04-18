package controller_test

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

const psTestNamespace = "default"

// TestPermissionSetReconciler_ValidSpec verifies that a valid PermissionSet reaches
// PermissionSetValid=True.
func TestPermissionSetReconciler_ValidSpec(t *testing.T) {
	ctx := context.Background()
	name := "test-ps-valid"

	ps := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: psTestNamespace,
		},
		Spec: securityv1alpha1.PermissionSetSpec{
			Description: "test permission set",
			Permissions: []securityv1alpha1.PermissionRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []securityv1alpha1.Verb{securityv1alpha1.VerbGet, securityv1alpha1.VerbList},
				},
			},
		},
	}
	if err := k8sClient.Create(ctx, ps); err != nil {
		t.Fatalf("failed to create PermissionSet: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, ps) })

	ok := poll(t, 10*time.Second, func() bool {
		var p securityv1alpha1.PermissionSet
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: psTestNamespace}, &p); err != nil {
			return false
		}
		c := securityv1alpha1.FindCondition(p.Status.Conditions, securityv1alpha1.ConditionTypePermissionSetValid)
		return c != nil && c.Status == metav1.ConditionTrue
	})
	if !ok {
		var p securityv1alpha1.PermissionSet
		_ = k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: psTestNamespace}, &p)
		t.Errorf("PermissionSet did not reach Valid=True; conditions: %+v", p.Status.Conditions)
	}
}

// TestPermissionSetReconciler_EmptyPermissions verifies that a PermissionSet with
// no permissions reaches PermissionSetValid=False.
func TestPermissionSetReconciler_EmptyPermissions(t *testing.T) {
	ctx := context.Background()
	name := "test-ps-empty-perms"

	ps := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: psTestNamespace,
		},
		Spec: securityv1alpha1.PermissionSetSpec{
			Permissions: []securityv1alpha1.PermissionRule{},
		},
	}
	if err := k8sClient.Create(ctx, ps); err != nil {
		t.Fatalf("failed to create PermissionSet: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, ps) })

	ok := poll(t, 10*time.Second, func() bool {
		var p securityv1alpha1.PermissionSet
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: psTestNamespace}, &p); err != nil {
			return false
		}
		c := securityv1alpha1.FindCondition(p.Status.Conditions, securityv1alpha1.ConditionTypePermissionSetValid)
		return c != nil && c.Status == metav1.ConditionFalse
	})
	if !ok {
		var p securityv1alpha1.PermissionSet
		_ = k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: psTestNamespace}, &p)
		t.Errorf("PermissionSet did not reach Valid=False; conditions: %+v", p.Status.Conditions)
	}
}

// TestPermissionSetReconciler_EmptyResources verifies that a PermissionSet with a rule
// missing Resources reaches PermissionSetValid=False.
func TestPermissionSetReconciler_EmptyResources(t *testing.T) {
	ctx := context.Background()
	name := "test-ps-empty-resources"

	ps := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: psTestNamespace,
		},
		Spec: securityv1alpha1.PermissionSetSpec{
			Permissions: []securityv1alpha1.PermissionRule{
				{
					APIGroups: []string{""},
					Resources: []string{}, // invalid: empty
					Verbs:     []securityv1alpha1.Verb{securityv1alpha1.VerbGet},
				},
			},
		},
	}
	if err := k8sClient.Create(ctx, ps); err != nil {
		t.Fatalf("failed to create PermissionSet: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, ps) })

	ok := poll(t, 10*time.Second, func() bool {
		var p securityv1alpha1.PermissionSet
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: psTestNamespace}, &p); err != nil {
			return false
		}
		c := securityv1alpha1.FindCondition(p.Status.Conditions, securityv1alpha1.ConditionTypePermissionSetValid)
		return c != nil && c.Status == metav1.ConditionFalse
	})
	if !ok {
		var p securityv1alpha1.PermissionSet
		_ = k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: psTestNamespace}, &p)
		t.Errorf("PermissionSet did not reach Valid=False; conditions: %+v", p.Status.Conditions)
	}
}

// TestPermissionSetReconciler_ProfileReferenceCount verifies that ProfileReferenceCount
// reflects the number of RBACProfiles referencing the PermissionSet by name.
func TestPermissionSetReconciler_ProfileReferenceCount(t *testing.T) {
	ctx := context.Background()
	psName := "test-ps-refcount"

	// Create the PermissionSet first.
	ps := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      psName,
			Namespace: psTestNamespace,
		},
		Spec: securityv1alpha1.PermissionSetSpec{
			Permissions: []securityv1alpha1.PermissionRule{
				{
					APIGroups: []string{""},
					Resources: []string{"secrets"},
					Verbs:     []securityv1alpha1.Verb{securityv1alpha1.VerbGet},
				},
			},
		},
	}
	if err := k8sClient.Create(ctx, ps); err != nil {
		t.Fatalf("failed to create PermissionSet: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, ps) })

	// Wait for initial reconcile (count=0).
	okInitial := poll(t, 10*time.Second, func() bool {
		var p securityv1alpha1.PermissionSet
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: psName, Namespace: psTestNamespace}, &p); err != nil {
			return false
		}
		c := securityv1alpha1.FindCondition(p.Status.Conditions, securityv1alpha1.ConditionTypePermissionSetValid)
		return c != nil && c.Status == metav1.ConditionTrue
	})
	if !okInitial {
		t.Fatal("PermissionSet did not reach Valid=True before profile creation")
	}

	// Create two RBACProfiles referencing this PermissionSet.
	profileA := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-profile-refcount-a",
			Namespace: psTestNamespace,
		},
		Spec: securityv1alpha1.RBACProfileSpec{
			PrincipalRef:   "principal-a",
			RBACPolicyRef:  "some-policy",
			TargetClusters: []string{"ccs-dev"},
			PermissionDeclarations: []securityv1alpha1.PermissionDeclaration{
				{PermissionSetRef: psName, Scope: securityv1alpha1.PermissionScopeNamespaced},
			},
		},
	}
	profileB := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-profile-refcount-b",
			Namespace: psTestNamespace,
		},
		Spec: securityv1alpha1.RBACProfileSpec{
			PrincipalRef:   "principal-b",
			RBACPolicyRef:  "some-policy",
			TargetClusters: []string{"ccs-dev"},
			PermissionDeclarations: []securityv1alpha1.PermissionDeclaration{
				{PermissionSetRef: psName, Scope: securityv1alpha1.PermissionScopeNamespaced},
				{PermissionSetRef: psName, Scope: securityv1alpha1.PermissionScopeCluster}, // same PS twice: count once
			},
		},
	}

	if err := k8sClient.Create(ctx, profileA); err != nil {
		t.Fatalf("failed to create profileA: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, profileA) })

	if err := k8sClient.Create(ctx, profileB); err != nil {
		t.Fatalf("failed to create profileB: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, profileB) })

	// Touch the PermissionSet to trigger re-reconcile (update annotation or label).
	// The GenerationChangedPredicate fires on spec changes. We need to trigger a
	// re-reconcile; patching an annotation on the spec-level won't change generation.
	// Instead update the description (changes spec → bumps generation).
	var latest securityv1alpha1.PermissionSet
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: psName, Namespace: psTestNamespace}, &latest); err != nil {
		t.Fatalf("failed to get PermissionSet for update: %v", err)
	}
	latest.Spec.Description = "triggered"
	if err := k8sClient.Update(ctx, &latest); err != nil {
		t.Fatalf("failed to update PermissionSet description: %v", err)
	}

	// Wait for ProfileReferenceCount to reach 2.
	okCount := poll(t, 10*time.Second, func() bool {
		var p securityv1alpha1.PermissionSet
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: psName, Namespace: psTestNamespace}, &p); err != nil {
			return false
		}
		return p.Status.ProfileReferenceCount == 2
	})
	if !okCount {
		var p securityv1alpha1.PermissionSet
		_ = k8sClient.Get(ctx, types.NamespacedName{Name: psName, Namespace: psTestNamespace}, &p)
		t.Errorf("expected ProfileReferenceCount=2; got %d", p.Status.ProfileReferenceCount)
	}
}
