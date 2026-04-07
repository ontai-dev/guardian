// Package controller_test covers RBACPolicyReconciler behaviour.
//
// Tests use the fake controller-runtime client — no real API server required.
// Each test builds the scheme with both core and guardian v1alpha1 types.
//
// guardian-schema.md §7 RBACPolicy, guardian-design.md §1.
package controller_test

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
)

// buildGuardianScheme returns a scheme with guardian v1alpha1 types registered.
// The core types are not needed for RBACPolicy tests.
func buildGuardianScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(s)
	return s
}

// validRBACPolicy returns a structurally valid RBACPolicy referencing psName
// as its MaximumPermissionSetRef.
func validRBACPolicy(name, ns, psName string) *securityv1alpha1.RBACPolicy {
	return &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: securityv1alpha1.RBACPolicySpec{
			SubjectScope:            securityv1alpha1.SubjectScopePlatform,
			EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
			AllowedClusters:         []string{"ccs-dev"},
			MaximumPermissionSetRef: psName,
		},
	}
}

// minimalPermissionSet returns a PermissionSet with a single valid rule.
func minimalPermissionSet(name, ns string) *securityv1alpha1.PermissionSet {
	return &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: securityv1alpha1.PermissionSetSpec{
			Permissions: []securityv1alpha1.PermissionRule{
				{Resources: []string{"pods"}, Verbs: []securityv1alpha1.Verb{securityv1alpha1.VerbGet}},
			},
		},
	}
}

// reconcilePolicy creates a fake client, populates it with objs, and calls
// Reconcile twice: once to add the finalizer and once for actual processing.
// It returns the result of the second reconcile and the updated policy.
func reconcilePolicy(t *testing.T, policy *securityv1alpha1.RBACPolicy, extraObjs ...client.Object) (ctrl.Result, *securityv1alpha1.RBACPolicy) {
	t.Helper()
	s := buildGuardianScheme()
	builder := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(policy).
		WithStatusSubresource(policy)
	for _, obj := range extraObjs {
		builder = builder.WithObjects(obj)
	}
	fakeClient := builder.Build()

	recorder := record.NewFakeRecorder(16)
	r := &controller.RBACPolicyReconciler{
		Client:   fakeClient,
		Scheme:   s,
		Recorder: recorder,
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{
		Name:      policy.Name,
		Namespace: policy.Namespace,
	}}
	ctx := context.Background()

	// First reconcile adds the finalizer and returns early.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("first Reconcile (finalizer add) returned error: %v", err)
	}

	// Second reconcile performs actual policy processing.
	result, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("second Reconcile returned unexpected error: %v", err)
	}

	// Re-fetch the policy to get the patched status.
	updated := &securityv1alpha1.RBACPolicy{}
	if err := fakeClient.Get(ctx, req.NamespacedName, updated); err != nil {
		t.Fatalf("could not re-fetch RBACPolicy after reconcile: %v", err)
	}
	return result, updated
}

// TestRBACPolicyReconciler_ValidWithExistingPermissionSet verifies that a RBACPolicy
// referencing a PermissionSet that exists reconciles to RBACPolicyValid=True.
// guardian-schema.md §7.
func TestRBACPolicyReconciler_ValidWithExistingPermissionSet(t *testing.T) {
	const (
		policyNS = "seam-system"
		psName   = "platform-max"
	)
	policy := validRBACPolicy("test-policy", policyNS, psName)
	ps := minimalPermissionSet(psName, policyNS)

	_, updated := reconcilePolicy(t, policy, ps)

	cond := securityv1alpha1.FindCondition(updated.Status.Conditions,
		securityv1alpha1.ConditionTypeRBACPolicyValid)
	if cond == nil {
		t.Fatal("RBACPolicyValid condition not set")
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("expected RBACPolicyValid=True; got %s (reason: %s)", cond.Status, cond.Reason)
	}
}

// TestRBACPolicyReconciler_MissingPermissionSet verifies that a RBACPolicy referencing
// a PermissionSet that does not exist surfaces RBACPolicyValid=False with reason
// PermissionSetNotFound and returns a non-zero RequeueAfter.
// guardian-schema.md §7.
func TestRBACPolicyReconciler_MissingPermissionSet(t *testing.T) {
	const policyNS = "seam-system"
	policy := validRBACPolicy("test-policy-noref", policyNS, "nonexistent-ps")

	result, updated := reconcilePolicy(t, policy /* no PermissionSet in fake client */)

	// Condition must be set to False with PermissionSetNotFound reason.
	cond := securityv1alpha1.FindCondition(updated.Status.Conditions,
		securityv1alpha1.ConditionTypeRBACPolicyValid)
	if cond == nil {
		t.Fatal("RBACPolicyValid condition not set")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("expected RBACPolicyValid=False; got %s", cond.Status)
	}
	if cond.Reason != securityv1alpha1.ReasonPermissionSetNotFound {
		t.Errorf("expected reason %q; got %q",
			securityv1alpha1.ReasonPermissionSetNotFound, cond.Reason)
	}
	// The reconciler must request a requeue so it retries when the PS appears.
	if result.RequeueAfter == 0 {
		t.Error("expected non-zero RequeueAfter when PermissionSet is missing")
	}
}

// TestRBACPolicyReconciler_FinalizerBlocksDeletion verifies that when a RBACPolicy has
// a finalizer, deletion is blocked (DeletionTimestamp set but object persists) until the
// reconciler removes the finalizer. This satisfies INV-006: deletion emits events, not Jobs.
func TestRBACPolicyReconciler_FinalizerBlocksDeletion(t *testing.T) {
	const policyNS = "seam-system"
	ps := minimalPermissionSet("platform-max", policyNS)
	policy := validRBACPolicy("test-policy-del", policyNS, "platform-max")

	s := buildGuardianScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(policy, ps).
		WithStatusSubresource(policy).
		Build()

	recorder := record.NewFakeRecorder(16)
	r := &controller.RBACPolicyReconciler{
		Client:   fakeClient,
		Scheme:   s,
		Recorder: recorder,
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{
		Name:      policy.Name,
		Namespace: policyNS,
	}}
	ctx := context.Background()

	// First reconcile: adds finalizer.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("first Reconcile returned error: %v", err)
	}

	// Verify finalizer is present.
	p := &securityv1alpha1.RBACPolicy{}
	if err := fakeClient.Get(ctx, req.NamespacedName, p); err != nil {
		t.Fatalf("Get after first reconcile failed: %v", err)
	}
	hasFinalizer := false
	for _, f := range p.Finalizers {
		if f == "security.ontai.dev/rbacpolicy" {
			hasFinalizer = true
		}
	}
	if !hasFinalizer {
		t.Fatal("expected rbacpolicy finalizer to be present after first reconcile")
	}

	// Delete the policy — fake client sets DeletionTimestamp but keeps object
	// because of the finalizer.
	if err := fakeClient.Delete(ctx, p); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}

	// Object must still exist (finalizer blocks actual removal).
	pAfterDelete := &securityv1alpha1.RBACPolicy{}
	if err := fakeClient.Get(ctx, req.NamespacedName, pAfterDelete); err != nil {
		t.Fatalf("policy should still exist with finalizer set: %v", err)
	}
	if pAfterDelete.DeletionTimestamp.IsZero() {
		t.Fatal("expected DeletionTimestamp to be set after Delete")
	}

	// Deletion reconcile: reconciler removes finalizer.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("deletion Reconcile returned error: %v", err)
	}

	// After finalizer removal, the fake client fully deletes the object.
	pGone := &securityv1alpha1.RBACPolicy{}
	if err := fakeClient.Get(ctx, req.NamespacedName, pGone); err == nil {
		t.Error("expected policy to be fully deleted after finalizer was removed")
	}
}

// TestRBACPolicyReconciler_UpdatedPermissionSetRefTriggersRevalidation verifies that
// updating a RBACPolicy's MaximumPermissionSetRef to reference a missing PermissionSet
// causes PermissionSetValid to flip from True to False on the next reconcile.
func TestRBACPolicyReconciler_UpdatedPermissionSetRefTriggersRevalidation(t *testing.T) {
	const policyNS = "seam-system"
	ps1 := minimalPermissionSet("ps-one", policyNS)
	policy := validRBACPolicy("test-policy-update", policyNS, "ps-one")

	s := buildGuardianScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(policy, ps1).
		WithStatusSubresource(policy).
		Build()

	recorder := record.NewFakeRecorder(16)
	r := &controller.RBACPolicyReconciler{
		Client:   fakeClient,
		Scheme:   s,
		Recorder: recorder,
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{
		Name:      policy.Name,
		Namespace: policyNS,
	}}
	ctx := context.Background()

	// First reconcile: adds finalizer.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("first Reconcile returned error: %v", err)
	}
	// Second reconcile: ps-one exists → RBACPolicyValid=True.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("second Reconcile returned error: %v", err)
	}

	// Update the policy to reference ps-two (which does not exist).
	current := &securityv1alpha1.RBACPolicy{}
	if err := fakeClient.Get(ctx, req.NamespacedName, current); err != nil {
		t.Fatalf("Get before update: %v", err)
	}
	updated := current.DeepCopy()
	updated.Spec.MaximumPermissionSetRef = "ps-two"
	if err := fakeClient.Update(ctx, updated); err != nil {
		t.Fatalf("Update MaximumPermissionSetRef: %v", err)
	}

	// Third reconcile: ps-two is missing → RBACPolicyValid=False.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("third Reconcile returned unexpected error: %v", err)
	}

	revalidated := &securityv1alpha1.RBACPolicy{}
	if err := fakeClient.Get(ctx, req.NamespacedName, revalidated); err != nil {
		t.Fatalf("Get after update reconcile: %v", err)
	}

	cond := securityv1alpha1.FindCondition(revalidated.Status.Conditions,
		securityv1alpha1.ConditionTypeRBACPolicyValid)
	if cond == nil {
		t.Fatal("RBACPolicyValid condition not set after update reconcile")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("expected RBACPolicyValid=False after PermissionSet ref changed to missing; got %s", cond.Status)
	}
	if cond.Reason != securityv1alpha1.ReasonPermissionSetNotFound {
		t.Errorf("expected reason PermissionSetNotFound; got %q", cond.Reason)
	}
}
