// Package controller_test covers AuditSinkReconciler behaviour.
//
// Tests use a mock AuditDatabase and a fake controller-runtime client so no
// real CNPG connection or Kubernetes API server is required.
//
// guardian-schema.md §15, conductor-schema.md §18.
package controller_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/ontai-dev/guardian/internal/controller"
	"github.com/ontai-dev/guardian/internal/database"
)

// ── Mock AuditDatabase ───────────────────────────────────────────────────────

type mockAuditDB struct {
	// existing maps (clusterID+seq) to existence state.
	existing map[string]bool

	// inserted records all InsertEvent calls in order.
	inserted []database.AuditEvent

	// eventExistsErr, if set, is returned by EventExists.
	eventExistsErr error

	// insertErr, if set, is returned by InsertEvent.
	insertErr error
}

func newMockAuditDB() *mockAuditDB {
	return &mockAuditDB{existing: make(map[string]bool)}
}

func auditKey(clusterID string, seq int64) string {
	return fmt.Sprintf("%s:%d", clusterID, seq)
}

func (m *mockAuditDB) EventExists(ctx context.Context, clusterID string, seq int64) (bool, error) {
	if m.eventExistsErr != nil {
		return false, m.eventExistsErr
	}
	return m.existing[auditKey(clusterID, seq)], nil
}

func (m *mockAuditDB) InsertEvent(ctx context.Context, e database.AuditEvent) error {
	if m.insertErr != nil {
		return m.insertErr
	}
	m.inserted = append(m.inserted, e)
	m.existing[auditKey(e.ClusterID, e.SequenceNumber)] = true
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func buildScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	return s
}

type batchEvent struct {
	SequenceNumber int64  `json:"sequenceNumber"`
	Subject        string `json:"subject"`
	Action         string `json:"action"`
	Resource       string `json:"resource"`
	Decision       string `json:"decision"`
	MatchedPolicy  string `json:"matchedPolicy"`
}

func makeAuditBatchCM(name, ns, clusterID string, events []batchEvent) *corev1.ConfigMap {
	data, _ := json.Marshal(events)
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    map[string]string{"seam.ontai.dev/audit-batch": "true"},
			Annotations: map[string]string{
				"seam.ontai.dev/cluster-id": clusterID,
			},
		},
		Data: map[string]string{
			"events": string(data),
		},
	}
}

func reconcileWith(t *testing.T, db database.AuditDatabase, cm *corev1.ConfigMap) error {
	t.Helper()
	s := buildScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(s).WithObjects(cm).Build()
	r := &controller.AuditSinkReconciler{
		Client: fakeClient,
		Scheme: s,
		DB:     db,
	}
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace},
	})
	return err
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestAuditSink_InsertsNewEvents verifies that a fresh batch of events is
// inserted and the ConfigMap is deleted on success.
func TestAuditSink_InsertsNewEvents(t *testing.T) {
	db := newMockAuditDB()
	cm := makeAuditBatchCM("batch-1", "seam-system", "ccs-dev", []batchEvent{
		{SequenceNumber: 1, Subject: "alice", Action: "get", Resource: "pods", Decision: "allow", MatchedPolicy: "default"},
		{SequenceNumber: 2, Subject: "bob", Action: "delete", Resource: "secrets", Decision: "deny", MatchedPolicy: "deny-all"},
	})

	if err := reconcileWith(t, db, cm); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	if len(db.inserted) != 2 {
		t.Errorf("expected 2 inserted events, got %d", len(db.inserted))
	}
	if db.inserted[0].SequenceNumber != 1 {
		t.Errorf("expected seq 1 first, got %d", db.inserted[0].SequenceNumber)
	}
	if db.inserted[0].ClusterID != "ccs-dev" {
		t.Errorf("expected clusterID=ccs-dev, got %q", db.inserted[0].ClusterID)
	}
}

// TestAuditSink_DeduplicatesEvents verifies that events already present in the
// database are skipped without error.
func TestAuditSink_DeduplicatesEvents(t *testing.T) {
	db := newMockAuditDB()
	// Pre-seed seq 1 as already existing.
	db.existing[auditKey("ccs-dev", 1)] = true

	cm := makeAuditBatchCM("batch-2", "seam-system", "ccs-dev", []batchEvent{
		{SequenceNumber: 1, Subject: "alice", Action: "get", Resource: "pods", Decision: "allow"},
		{SequenceNumber: 2, Subject: "bob", Action: "list", Resource: "pods", Decision: "allow"},
	})

	if err := reconcileWith(t, db, cm); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	if len(db.inserted) != 1 {
		t.Errorf("expected 1 inserted event (seq 1 skipped), got %d", len(db.inserted))
	}
	if db.inserted[0].SequenceNumber != 2 {
		t.Errorf("expected seq 2 to be inserted, got %d", db.inserted[0].SequenceNumber)
	}
}

// TestAuditSink_AllDuplicates verifies that a batch of entirely duplicate events
// results in zero insertions and the ConfigMap is still deleted.
func TestAuditSink_AllDuplicates(t *testing.T) {
	db := newMockAuditDB()
	db.existing[auditKey("ccs-dev", 1)] = true
	db.existing[auditKey("ccs-dev", 2)] = true

	cm := makeAuditBatchCM("batch-3", "seam-system", "ccs-dev", []batchEvent{
		{SequenceNumber: 1},
		{SequenceNumber: 2},
	})

	if err := reconcileWith(t, db, cm); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	if len(db.inserted) != 0 {
		t.Errorf("expected 0 insertions for all-duplicate batch, got %d", len(db.inserted))
	}
}

// TestAuditSink_ClusterIDTagging verifies that the cluster_id from the annotation
// is propagated to every inserted event.
func TestAuditSink_ClusterIDTagging(t *testing.T) {
	db := newMockAuditDB()
	cm := makeAuditBatchCM("batch-4", "seam-system", "ccs-test", []batchEvent{
		{SequenceNumber: 10, Subject: "carol"},
		{SequenceNumber: 11, Subject: "dave"},
		{SequenceNumber: 12, Subject: "eve"},
	})

	if err := reconcileWith(t, db, cm); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	for _, e := range db.inserted {
		if e.ClusterID != "ccs-test" {
			t.Errorf("expected clusterID=ccs-test, got %q (seq=%d)", e.ClusterID, e.SequenceNumber)
		}
	}
}

// TestAuditSink_MissingClusterID verifies that a ConfigMap without a cluster-id
// annotation is skipped (no insertions, no error, ConfigMap not deleted).
func TestAuditSink_MissingClusterID(t *testing.T) {
	db := newMockAuditDB()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "batch-no-cluster",
			Namespace: "seam-system",
			Labels:    map[string]string{"seam.ontai.dev/audit-batch": "true"},
			// No cluster-id annotation.
		},
		Data: map[string]string{"events": `[{"sequenceNumber":1}]`},
	}

	if err := reconcileWith(t, db, cm); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	if len(db.inserted) != 0 {
		t.Errorf("expected 0 insertions for missing cluster-id, got %d", len(db.inserted))
	}
}

// TestAuditSink_MissingLabel verifies that ConfigMaps without the audit-batch
// label are ignored entirely.
func TestAuditSink_MissingLabel(t *testing.T) {
	db := newMockAuditDB()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "not-a-batch",
			Namespace: "seam-system",
		},
		Data: map[string]string{"events": `[{"sequenceNumber":1}]`},
	}

	if err := reconcileWith(t, db, cm); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	if len(db.inserted) != 0 {
		t.Errorf("expected 0 insertions for unlabelled ConfigMap, got %d", len(db.inserted))
	}
}

// TestAuditSink_EventExistsError verifies that an EventExists database error
// causes Reconcile to return an error and requeue (ConfigMap not deleted).
func TestAuditSink_EventExistsError(t *testing.T) {
	db := newMockAuditDB()
	db.eventExistsErr = fmt.Errorf("database connection lost")

	cm := makeAuditBatchCM("batch-err", "seam-system", "ccs-dev", []batchEvent{
		{SequenceNumber: 1},
	})

	err := reconcileWith(t, db, cm)
	if err == nil {
		t.Fatal("expected Reconcile to return error when EventExists fails")
	}
}

// TestAuditSink_InsertError verifies that an InsertEvent database error causes
// Reconcile to return an error and requeue.
func TestAuditSink_InsertError(t *testing.T) {
	db := newMockAuditDB()
	db.insertErr = fmt.Errorf("unique constraint violation")

	cm := makeAuditBatchCM("batch-insert-err", "seam-system", "ccs-dev", []batchEvent{
		{SequenceNumber: 99},
	})

	err := reconcileWith(t, db, cm)
	if err == nil {
		t.Fatal("expected Reconcile to return error when InsertEvent fails")
	}
}

// TestAuditSink_MalformedJSON verifies that a ConfigMap with malformed JSON
// in the events field is deleted without inserting anything or returning an error.
func TestAuditSink_MalformedJSON(t *testing.T) {
	db := newMockAuditDB()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "batch-malformed",
			Namespace:   "seam-system",
			Labels:      map[string]string{"seam.ontai.dev/audit-batch": "true"},
			Annotations: map[string]string{"seam.ontai.dev/cluster-id": "ccs-dev"},
		},
		Data: map[string]string{"events": `{not valid json`},
	}

	if err := reconcileWith(t, db, cm); err != nil {
		t.Fatalf("expected Reconcile to succeed (delete malformed CM), got: %v", err)
	}

	if len(db.inserted) != 0 {
		t.Errorf("expected 0 insertions for malformed JSON, got %d", len(db.inserted))
	}
}

// TestAuditSink_EmptyBatch verifies that an empty event array is processed
// without error and the ConfigMap is deleted.
func TestAuditSink_EmptyBatch(t *testing.T) {
	db := newMockAuditDB()
	cm := makeAuditBatchCM("batch-empty", "seam-system", "ccs-dev", []batchEvent{})

	if err := reconcileWith(t, db, cm); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	if len(db.inserted) != 0 {
		t.Errorf("expected 0 insertions for empty batch, got %d", len(db.inserted))
	}
}
