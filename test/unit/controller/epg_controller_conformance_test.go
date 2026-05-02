// Package controller_test covers EPGReconciler conformance with the formal
// PermissionSnapshot CRD schema defined in guardian schema §7 (commit 0fd9cd1).
//
// This file verifies that after a full EPG computation cycle, the upserted
// PermissionSnapshot CR conforms to the formal CRD schema:
//   - spec.targetCluster is non-empty and matches the expected cluster
//   - spec.snapshotTimestamp is non-zero
//   - spec.subjects is non-empty
//   - each SubjectEntry has a non-empty SubjectName, a valid SubjectKind, and
//     at least one PermissionEntry
//
// guardian-schema.md §7, guardian-design.md §2.
package controller_test

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientevents "k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
)

// validSubjectKinds is the set of valid SubjectKind values from the formal CRD schema.
var validSubjectKinds = map[securityv1alpha1.SubjectKind]bool{
	securityv1alpha1.SubjectKindServiceAccount: true,
	securityv1alpha1.SubjectKindUser:           true,
	securityv1alpha1.SubjectKindGroup:          true,
}

// TestEPGReconciler_PermissionSnapshotConformsToFormalSchema verifies that after a
// full EPG computation triggered by the "epg-trigger" reconcile key, the resulting
// PermissionSnapshot CR conforms to the formal CRD schema (guardian schema §7).
//
// This is the pre-lab compatibility test: it confirms that guardian's EPGReconciler
// produces PermissionSnapshots that conductor's SnapshotPullLoop can consume using
// the formal spec.subjects field.
func TestEPGReconciler_PermissionSnapshotConformsToFormalSchema(t *testing.T) {
	const (
		ns          = "security-system"
		clusterName = "ccs-test"
		principal   = "alice"
		policyName  = "test-policy"
		psName      = "test-permset"
	)

	// Build prerequisite objects.
	permSet := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{Name: psName, Namespace: ns},
		Spec: securityv1alpha1.PermissionSetSpec{
			Permissions: []securityv1alpha1.PermissionRule{
				{
					Resources: []string{"pods"},
					Verbs:     []securityv1alpha1.Verb{securityv1alpha1.VerbGet, securityv1alpha1.VerbList},
				},
				{
					APIGroups: []string{"apps"},
					Resources: []string{"deployments"},
					Verbs:     []securityv1alpha1.Verb{securityv1alpha1.VerbGet},
				},
			},
		},
	}

	policy := &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: ns},
		Spec: securityv1alpha1.RBACPolicySpec{
			SubjectScope:            securityv1alpha1.SubjectScopeTenant,
			EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
			AllowedClusters:         []string{clusterName},
			MaximumPermissionSetRef: psName,
		},
	}

	// RBACProfile with Status.Provisioned=true so EPGReconciler picks it up.
	profile := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "profile-alice", Namespace: ns},
		Spec: securityv1alpha1.RBACProfileSpec{
			PrincipalRef:   principal,
			RBACPolicyRef:  policyName,
			TargetClusters: []string{clusterName},
			PermissionDeclarations: []securityv1alpha1.PermissionDeclaration{
				{
					PermissionSetRef: psName,
					Scope:            securityv1alpha1.PermissionScopeCluster,
				},
			},
		},
		Status: securityv1alpha1.RBACProfileStatus{
			Provisioned: true,
		},
	}

	s := buildGuardianScheme()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(permSet, policy, profile).
		WithStatusSubresource(profile, &securityv1alpha1.PermissionSnapshot{}).
		Build()

	r := &controller.EPGReconciler{
		Client:            cl,
		Scheme:            s,
		Recorder:          clientevents.NewFakeRecorder(16),
		OperatorNamespace: ns,
	}

	// Trigger a full EPG recomputation via the "epg-trigger" fixed key.
	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "epg-trigger", Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("unexpected RequeueAfter %v; wanted 0", result.RequeueAfter)
	}

	// Retrieve the upserted PermissionSnapshot.
	// EPGReconciler uses server-side apply (Patch); the fake client handles it.
	var snapList securityv1alpha1.PermissionSnapshotList
	if err := cl.List(context.Background(), &snapList, client.InNamespace(ns)); err != nil {
		t.Fatalf("List PermissionSnapshots: %v", err)
	}
	if len(snapList.Items) == 0 {
		t.Fatal("no PermissionSnapshot created after EPG reconcile")
	}

	// Find the snapshot for ccs-test.
	var snap *securityv1alpha1.PermissionSnapshot
	for i := range snapList.Items {
		if snapList.Items[i].Spec.TargetCluster == clusterName {
			snap = &snapList.Items[i]
			break
		}
	}
	if snap == nil {
		t.Fatalf("no PermissionSnapshot with TargetCluster=%q found", clusterName)
	}

	// ── Formal schema assertions ────────────────────────────────────────────

	// 1. TargetCluster must be non-empty and match the expected cluster.
	if snap.Spec.TargetCluster == "" {
		t.Error("spec.targetCluster is empty; must be non-empty")
	}
	if snap.Spec.TargetCluster != clusterName {
		t.Errorf("spec.targetCluster: got %q; want %q", snap.Spec.TargetCluster, clusterName)
	}

	// 2. SnapshotTimestamp must be set and non-zero.
	if snap.Spec.SnapshotTimestamp == nil {
		t.Error("spec.snapshotTimestamp is nil; must be set by BuildPermissionSnapshot")
	} else if snap.Spec.SnapshotTimestamp.IsZero() {
		t.Error("spec.snapshotTimestamp is zero; must be non-zero")
	} else if snap.Spec.SnapshotTimestamp.After(time.Now().Add(time.Minute)) {
		t.Errorf("spec.snapshotTimestamp %v is in the future; likely a clock bug",
			snap.Spec.SnapshotTimestamp)
	}

	// 3. Subjects must be non-empty.
	if len(snap.Spec.Subjects) == 0 {
		t.Fatal("spec.subjects is empty; EPGReconciler must populate it from computed EPG")
	}

	// 4. Each SubjectEntry must have a valid SubjectName, SubjectKind, and at least
	//    one PermissionEntry.
	for i, sub := range snap.Spec.Subjects {
		if sub.SubjectName == "" {
			t.Errorf("subjects[%d].subjectName is empty; must be non-empty", i)
		}
		if !validSubjectKinds[sub.SubjectKind] {
			t.Errorf("subjects[%d].subjectKind %q is not a valid SubjectKind (ServiceAccount|User|Group)",
				i, sub.SubjectKind)
		}
		if len(sub.Permissions) == 0 {
			t.Errorf("subjects[%d] (%q) has no PermissionEntries; must have at least one", i, sub.SubjectName)
		}
		for j, perm := range sub.Permissions {
			if len(perm.Resources) == 0 {
				t.Errorf("subjects[%d].permissions[%d].resources is empty", i, j)
			}
			if len(perm.Verbs) == 0 {
				t.Errorf("subjects[%d].permissions[%d].verbs is empty", i, j)
			}
		}
	}

	// 5. The principal from the RBACProfile must appear in Subjects.
	found := false
	for _, sub := range snap.Spec.Subjects {
		if sub.SubjectName == principal {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("principal %q not found in spec.subjects; EPG computation must include it", principal)
	}
}

// TestEPGReconciler_ManagementClusterSnapshotAlias verifies G-BL-SNAPSHOT-ALIAS:
// when ManagementClusterName is set and the target cluster matches, the
// PermissionSnapshot is named "snapshot-management" instead of "snapshot-{cluster}".
func TestEPGReconciler_ManagementClusterSnapshotAlias(t *testing.T) {
	const (
		ns          = "security-system"
		mgmtCluster = "ccs-mgmt"
		psName      = "ps-alias-test"
		policyName  = "policy-alias-test"
	)

	permSet := &securityv1alpha1.PermissionSet{
		ObjectMeta: metav1.ObjectMeta{Name: psName, Namespace: ns},
		Spec: securityv1alpha1.PermissionSetSpec{
			Permissions: []securityv1alpha1.PermissionRule{
				{Resources: []string{"pods"}, Verbs: []securityv1alpha1.Verb{securityv1alpha1.VerbGet}},
			},
		},
	}
	policy := &securityv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: ns},
		Spec: securityv1alpha1.RBACPolicySpec{
			SubjectScope:            securityv1alpha1.SubjectScopeTenant,
			EnforcementMode:         securityv1alpha1.EnforcementModeStrict,
			AllowedClusters:         []string{mgmtCluster},
			MaximumPermissionSetRef: psName,
		},
	}
	profile := &securityv1alpha1.RBACProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "profile-mgmt", Namespace: ns},
		Spec: securityv1alpha1.RBACProfileSpec{
			PrincipalRef:   "mgmt-user",
			RBACPolicyRef:  policyName,
			TargetClusters: []string{mgmtCluster},
			PermissionDeclarations: []securityv1alpha1.PermissionDeclaration{
				{PermissionSetRef: psName, Scope: securityv1alpha1.PermissionScopeCluster},
			},
		},
		Status: securityv1alpha1.RBACProfileStatus{Provisioned: true},
	}

	s := buildGuardianScheme()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(permSet, policy, profile).
		WithStatusSubresource(profile, &securityv1alpha1.PermissionSnapshot{}).
		Build()

	r := &controller.EPGReconciler{
		Client:                cl,
		Scheme:                s,
		Recorder:              clientevents.NewFakeRecorder(16),
		OperatorNamespace:     ns,
		ManagementClusterName: mgmtCluster,
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "epg-trigger", Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	// The snapshot must be named "snapshot-management", not "snapshot-ccs-mgmt".
	var snapList securityv1alpha1.PermissionSnapshotList
	if err := cl.List(context.Background(), &snapList, client.InNamespace(ns)); err != nil {
		t.Fatalf("List PermissionSnapshots: %v", err)
	}
	if len(snapList.Items) == 0 {
		t.Fatal("no PermissionSnapshot created")
	}
	snap := &snapList.Items[0]
	if snap.Name != "snapshot-management" {
		t.Errorf("snapshot name: got %q; want %q", snap.Name, "snapshot-management")
	}
	if snap.Spec.TargetCluster != mgmtCluster {
		t.Errorf("spec.targetCluster: got %q; want %q", snap.Spec.TargetCluster, mgmtCluster)
	}
}
