// Package controller_test verifies that reconciler audit events carry lineageIndexRef
// for governed-object events. guardian-schema.md §17.
//
// Tests:
//  1. RBACPolicyReconciler -- validation_failed event carries lineageIndexRef.
//  2. RBACPolicyReconciler -- validated event carries lineageIndexRef.
//  3. RBACProfileReconciler -- provisioned event carries lineageIndexRef.
//  4. RBACPolicyReconciler -- lineageIndexRef.Name follows IndexName convention.
package controller_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientevents "k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
	"github.com/ontai-dev/guardian/internal/database"
)

// TestAuditLineage_RBACPolicyValidationFailedCarriesRef verifies that when an
// RBACPolicy has a structurally invalid spec, the audit event for validation_failed
// carries a non-nil lineageIndexRef.
func TestAuditLineage_RBACPolicyValidationFailedCarriesRef(t *testing.T) {
	ns := "seam-system"
	// A policy with an empty spec will fail validation.
	policy := &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bad-policy",
			Namespace: ns,
		},
		Spec: securityv1alpha1.RBACPolicySpec{},
	}

	s := buildGuardianScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(policy).
		WithStatusSubresource(&securityv1alpha1.RBACPolicy{}).
		Build()

	aw := &testAuditWriter{}
	r := &controller.RBACPolicyReconciler{
		Client:      c,
		Scheme:      s,
		Recorder:    clientevents.NewFakeRecorder(32),
		AuditWriter: aw,
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "bad-policy", Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var found *database.AuditEvent
	for _, e := range aw.written() {
		if e.Action == "rbacpolicy.validation_failed" {
			e := e
			found = &e
			break
		}
	}
	if found == nil {
		t.Fatal("expected audit event action=rbacpolicy.validation_failed, got none")
	}
	if found.LineageIndexRef == nil {
		t.Fatal("LineageIndexRef must not be nil for rbacpolicy.validation_failed event")
	}
	if found.LineageIndexRef.Namespace != ns {
		t.Errorf("LineageIndexRef.Namespace = %q, want %q", found.LineageIndexRef.Namespace, ns)
	}
}

// TestAuditLineage_RBACPolicyValidatedCarriesRef verifies that when an RBACPolicy
// passes validation, the audit event for validated carries a non-nil lineageIndexRef.
func TestAuditLineage_RBACPolicyValidatedCarriesRef(t *testing.T) {
	ns := "seam-system"
	ps := minimalPermissionSet("exec-ps", ns)
	policy := validRBACPolicy("good-policy", ns, "exec-ps")

	s := buildGuardianScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(policy, ps).
		WithStatusSubresource(&securityv1alpha1.RBACPolicy{}).
		Build()

	aw := &testAuditWriter{}
	r := &controller.RBACPolicyReconciler{
		Client:      c,
		Scheme:      s,
		Recorder:    clientevents.NewFakeRecorder(32),
		AuditWriter: aw,
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "good-policy", Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var found *database.AuditEvent
	for _, e := range aw.written() {
		if e.Action == "rbacpolicy.validated" {
			e := e
			found = &e
			break
		}
	}
	if found == nil {
		t.Fatal("expected audit event action=rbacpolicy.validated, got none")
	}
	if found.LineageIndexRef == nil {
		t.Fatal("LineageIndexRef must not be nil for rbacpolicy.validated event")
	}
	if found.LineageIndexRef.Namespace != ns {
		t.Errorf("LineageIndexRef.Namespace = %q, want %q", found.LineageIndexRef.Namespace, ns)
	}
}

// TestAuditLineage_RBACProfileProvisionedCarriesRef verifies that on a successful
// provision, the rbacprofile.provisioned audit event carries a non-nil lineageIndexRef.
func TestAuditLineage_RBACProfileProvisionedCarriesRef(t *testing.T) {
	profile, policy, ps := provisionedFixture(t)
	ns := "seam-system"

	s := buildProvisioningScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(profile, policy, ps).
		WithStatusSubresource(&securityv1alpha1.RBACProfile{}).
		Build()

	aw := &testAuditWriter{}
	r := &controller.RBACProfileReconciler{
		Client:      c,
		Scheme:      s,
		Recorder:    clientevents.NewFakeRecorder(32),
		AuditWriter: aw,
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-profile", Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var found *database.AuditEvent
	for _, e := range aw.written() {
		if e.Action == "rbacprofile.provisioned" {
			e := e
			found = &e
			break
		}
	}
	if found == nil {
		t.Fatal("expected audit event action=rbacprofile.provisioned, got none")
	}
	if found.LineageIndexRef == nil {
		t.Fatal("LineageIndexRef must not be nil for rbacprofile.provisioned event")
	}
	if found.LineageIndexRef.Namespace != ns {
		t.Errorf("LineageIndexRef.Namespace = %q, want %q", found.LineageIndexRef.Namespace, ns)
	}
}

// TestAuditLineage_LineageIndexRefNameFollowsConvention verifies that the
// lineageIndexRef.Name for an RBACPolicy event follows the IndexName convention:
// strings.ToLower(kind) + "-" + name.
func TestAuditLineage_LineageIndexRefNameFollowsConvention(t *testing.T) {
	ns := "seam-system"
	ps := minimalPermissionSet("exec-ps", ns)
	policy := validRBACPolicy("my-policy", ns, "exec-ps")

	s := buildGuardianScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(policy, ps).
		WithStatusSubresource(&securityv1alpha1.RBACPolicy{}).
		Build()

	aw := &testAuditWriter{}
	r := &controller.RBACPolicyReconciler{
		Client:      c,
		Scheme:      s,
		Recorder:    clientevents.NewFakeRecorder(32),
		AuditWriter: aw,
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-policy", Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	want := fmt.Sprintf("%s-%s", strings.ToLower("RBACPolicy"), "my-policy")
	for _, e := range aw.written() {
		if e.LineageIndexRef == nil {
			continue
		}
		if e.LineageIndexRef.Name != want {
			t.Errorf("LineageIndexRef.Name = %q, want %q", e.LineageIndexRef.Name, want)
		}
	}
}
