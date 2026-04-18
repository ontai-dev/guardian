package controller_test

// Scenario 2 — CRD schema admission rejection.
// Scenario 6 — RBACPolicy finalizer lifecycle.

import (
	"context"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

// TestCRDAdmission_RBACPolicyMissingRequiredField_Rejected verifies that the
// API server rejects a RBACPolicy CR that omits a required spec field before
// the object is persisted in etcd. The rejection is enforced by the CRD
// OpenAPI schema (not an admission webhook), so no reconciler involvement is
// needed — the Create call returns an error immediately.
//
// Required fields per security.ontai.dev_rbacpolicies.yaml: enforcementMode,
// maximumPermissionSetRef, subjectScope. Omitting subjectScope triggers the
// CRD schema validator at the API server admission layer.
//
// This test verifies that the object is NEVER visible in etcd: a subsequent
// Get returns NotFound, confirming the rejection was pre-persistence.
// Scenario 2 — Test Session F.
func TestCRDAdmission_RBACPolicyMissingRequiredField_Rejected(t *testing.T) {
	ctx := context.Background()

	// Attempt to create a RBACPolicy that omits the required subjectScope field.
	// The CRD schema requires: enforcementMode, maximumPermissionSetRef, subjectScope.
	// We supply only enforcementMode + maximumPermissionSetRef — subjectScope is absent.
	invalid := &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "crd-admission-missing-subject-scope",
			Namespace: "default",
		},
		Spec: securityv1alpha1.RBACPolicySpec{
			// SubjectScope deliberately omitted — CRD schema requires it.
			EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
			MaximumPermissionSetRef: "some-permset",
		},
	}

	err := k8sClient.Create(ctx, invalid)
	if err == nil {
		// Object was unexpectedly accepted — clean up and fail.
		t.Cleanup(func() { _ = k8sClient.Delete(ctx, invalid) })
		t.Fatal("expected CRD schema validation error for missing subjectScope; Create succeeded")
	}

	// The error must be a validation error from the API server — not a network
	// or client error. apierrors.IsInvalid() covers CRD schema rejections.
	if !apierrors.IsInvalid(err) && !apierrors.IsBadRequest(err) {
		t.Errorf("expected Invalid/BadRequest error from API server CRD schema validation; got: %v", err)
	}

	// Confirm the object is not in etcd: a subsequent Get must return NotFound.
	nn := types.NamespacedName{Name: invalid.Name, Namespace: invalid.Namespace}
	got := &securityv1alpha1.RBACPolicy{}
	getErr := k8sClient.Get(ctx, nn, got)
	if !apierrors.IsNotFound(getErr) {
		t.Errorf("expected object to be absent from etcd after rejection; Get returned: %v", getErr)
	}
}

// TestRBACPolicyFinalizer_DeleteRemovesFinalizer verifies the full finalizer
// lifecycle for RBACPolicy:
//  1. The reconciler adds the security.ontai.dev/rbacpolicy finalizer on first
//     observation (visible via the API server).
//  2. Issuing a Delete sets DeletionTimestamp while the finalizer blocks GC.
//  3. The reconciler detects DeletionTimestamp, emits an event, removes the
//     finalizer, and calls r.Client.Update.
//  4. After finalizer removal the object is fully deleted from etcd —
//     a subsequent Get returns NotFound.
//
// This test validates behavior that fake clients cannot reproduce: real
// DeletionTimestamp semantics, real etcd GC, and real status-patch ordering.
// Scenario 6 — Test Session F.
func TestRBACPolicyFinalizer_DeleteRemovesFinalizer(t *testing.T) {
	ctx := context.Background()
	ns := "default"

	// Create a PermissionSet so the policy reconciles to a terminal condition
	// quickly without blocking on PermissionSetNotFound.
	ps := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{Name: "finalizer-test-ps", Namespace: ns},
		Spec: securityv1alpha1.PermissionSetSpec{
			Permissions: []securityv1alpha1.PermissionRule{
				{Resources: []string{"configmaps"}, Verbs: []securityv1alpha1.Verb{"get"}},
			},
		},
	}
	if err := k8sClient.Create(ctx, ps); err != nil {
		t.Fatalf("create PermissionSet: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, ps) })

	policy := &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "finalizer-lifecycle-test",
			Namespace: ns,
		},
		Spec: securityv1alpha1.RBACPolicySpec{
			SubjectScope:            securityv1alpha1.SubjectScopePlatform,
			EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
			AllowedClusters:         []string{},
			MaximumPermissionSetRef: "finalizer-test-ps",
		},
	}
	if err := k8sClient.Create(ctx, policy); err != nil {
		t.Fatalf("create RBACPolicy: %v", err)
	}

	nn := types.NamespacedName{Name: policy.Name, Namespace: ns}

	// Step 1 — Wait for the reconciler to add the finalizer.
	// The reconciler adds security.ontai.dev/rbacpolicy on first observation
	// before processing the rest of the reconcile loop.
	ok := poll(t, 10*time.Second, func() bool {
		got := &securityv1alpha1.RBACPolicy{}
		if err := k8sClient.Get(ctx, nn, got); err != nil {
			return false
		}
		for _, f := range got.Finalizers {
			if f == "security.ontai.dev/rbacpolicy" {
				return true
			}
		}
		return false
	})
	if !ok {
		got := &securityv1alpha1.RBACPolicy{}
		_ = k8sClient.Get(ctx, nn, got)
		t.Fatalf("timed out waiting for finalizer; finalizers=%v", got.Finalizers)
	}

	// Step 2 — Issue Delete. The API server sets DeletionTimestamp and holds
	// the object in etcd while the finalizer is still present.
	if err := k8sClient.Delete(ctx, policy); err != nil {
		t.Fatalf("Delete RBACPolicy: %v", err)
	}

	// Step 3 — Confirm DeletionTimestamp is set while finalizer still blocks.
	// This confirms the real etcd GC semantics — fake clients don't do this.
	gotMid := &securityv1alpha1.RBACPolicy{}
	if err := k8sClient.Get(ctx, nn, gotMid); err == nil {
		if gotMid.DeletionTimestamp.IsZero() {
			t.Error("expected DeletionTimestamp to be set immediately after Delete")
		}
	}

	// Step 4 — Wait for the reconciler to remove the finalizer and the object
	// to be fully deleted from etcd. Get must return NotFound.
	ok = poll(t, 15*time.Second, func() bool {
		got := &securityv1alpha1.RBACPolicy{}
		err := k8sClient.Get(ctx, nn, got)
		return apierrors.IsNotFound(err)
	})
	if !ok {
		got := &securityv1alpha1.RBACPolicy{}
		_ = k8sClient.Get(ctx, nn, got)
		t.Errorf("timed out waiting for object to be gone from etcd; finalizers=%v DeletionTimestamp=%v",
			got.Finalizers, got.DeletionTimestamp)
	}
}
