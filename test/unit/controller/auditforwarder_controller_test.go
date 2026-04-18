// Package controller_test covers AuditForwarderController behaviour.
//
// Tests use a fake controller-runtime client and drive the flush loop by
// sending events through the in-memory channel. No real Kubernetes API server
// or CNPG connection is required.
//
// guardian-schema.md §15, conductor-schema.md §18.
package controller_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/ontai-dev/guardian/internal/controller"
)

func buildForwarderScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	return s
}

// TestAuditForwarder_FlushOnInterval verifies that pending events are written
// to a ConfigMap after the flush interval elapses.
func TestAuditForwarder_FlushOnInterval(t *testing.T) {
	s := buildForwarderScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(s).Build()
	ch := make(chan controller.AuditForwarderEvent, 10)

	c := &controller.AuditForwarderController{
		Client:        fakeClient,
		EventCh:       ch,
		ClusterID:     "ccs-dev",
		FlushInterval: 50 * time.Millisecond,
		BatchSize:     100,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() { _ = c.Start(ctx) }()

	ch <- controller.AuditForwarderEvent{Subject: "alice", Action: "get", Resource: "pods", Decision: "allow"}
	ch <- controller.AuditForwarderEvent{Subject: "bob", Action: "list", Resource: "secrets", Decision: "deny"}
	ch <- controller.AuditForwarderEvent{Subject: "carol", Action: "create", Resource: "pods", Decision: "allow"}

	time.Sleep(200 * time.Millisecond)

	cmList := &corev1.ConfigMapList{}
	if err := fakeClient.List(ctx, cmList); err != nil {
		t.Fatalf("List ConfigMaps: %v", err)
	}
	if len(cmList.Items) == 0 {
		t.Fatal("expected at least one audit batch ConfigMap after flush interval")
	}

	cm := &cmList.Items[0]
	if cm.Labels["seam.ontai.dev/audit-batch"] != "true" {
		t.Errorf("expected audit-batch=true label, got %q", cm.Labels["seam.ontai.dev/audit-batch"])
	}
	if cm.Annotations["seam.ontai.dev/cluster-id"] != "ccs-dev" {
		t.Errorf("expected cluster-id=ccs-dev annotation, got %q", cm.Annotations["seam.ontai.dev/cluster-id"])
	}
	if _, ok := cm.Data["events"]; !ok {
		t.Error("expected 'events' key in ConfigMap data")
	}
}

// TestAuditForwarder_FlushOnBatchSize verifies that a batch flushes immediately
// when the batch size threshold is reached, before the interval elapses.
func TestAuditForwarder_FlushOnBatchSize(t *testing.T) {
	s := buildForwarderScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(s).Build()
	ch := make(chan controller.AuditForwarderEvent, 10)

	c := &controller.AuditForwarderController{
		Client:        fakeClient,
		EventCh:       ch,
		ClusterID:     "ccs-test",
		FlushInterval: 10 * time.Second,
		BatchSize:     3,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() { _ = c.Start(ctx) }()

	ch <- controller.AuditForwarderEvent{Subject: "a"}
	ch <- controller.AuditForwarderEvent{Subject: "b"}
	ch <- controller.AuditForwarderEvent{Subject: "c"}

	time.Sleep(100 * time.Millisecond)

	cmList := &corev1.ConfigMapList{}
	if err := fakeClient.List(ctx, cmList); err != nil {
		t.Fatalf("List ConfigMaps: %v", err)
	}
	if len(cmList.Items) == 0 {
		t.Fatal("expected audit batch ConfigMap after batch size threshold")
	}
}

// TestAuditForwarder_ConfigMapContents verifies the structure of the written ConfigMap:
// correct label, cluster-id annotation, and parseable events JSON.
func TestAuditForwarder_ConfigMapContents(t *testing.T) {
	s := buildForwarderScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(s).Build()
	ch := make(chan controller.AuditForwarderEvent, 10)

	c := &controller.AuditForwarderController{
		Client:        fakeClient,
		EventCh:       ch,
		ClusterID:     "ccs-dev",
		FlushInterval: 30 * time.Millisecond,
		BatchSize:     100,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() { _ = c.Start(ctx) }()

	ch <- controller.AuditForwarderEvent{
		Subject: "alice", Action: "delete", Resource: "pods",
		Decision: "deny", MatchedPolicy: "no-delete",
	}

	time.Sleep(150 * time.Millisecond)

	cmList := &corev1.ConfigMapList{}
	if err := fakeClient.List(ctx, cmList); err != nil {
		t.Fatalf("List ConfigMaps: %v", err)
	}
	if len(cmList.Items) == 0 {
		t.Fatal("no ConfigMap written")
	}

	cm := &cmList.Items[0]

	eventsRaw, ok := cm.Data["events"]
	if !ok {
		t.Fatal("ConfigMap data missing 'events' key")
	}
	var events []struct {
		SequenceNumber int64  `json:"sequenceNumber"`
		Subject        string `json:"subject"`
		Action         string `json:"action"`
		Resource       string `json:"resource"`
		Decision       string `json:"decision"`
		MatchedPolicy  string `json:"matchedPolicy"`
	}
	if err := json.Unmarshal([]byte(eventsRaw), &events); err != nil {
		t.Fatalf("failed to parse events JSON: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event in batch, got %d", len(events))
	}
	e := events[0]
	if e.Subject != "alice" {
		t.Errorf("expected subject=alice, got %q", e.Subject)
	}
	if e.Action != "delete" {
		t.Errorf("expected action=delete, got %q", e.Action)
	}
	if e.Decision != "deny" {
		t.Errorf("expected decision=deny, got %q", e.Decision)
	}
	if e.MatchedPolicy != "no-delete" {
		t.Errorf("expected matchedPolicy=no-delete, got %q", e.MatchedPolicy)
	}
}

// TestAuditForwarder_EmptyFlushNoConfigMap verifies that a flush with no pending
// events does not write a ConfigMap.
func TestAuditForwarder_EmptyFlushNoConfigMap(t *testing.T) {
	s := buildForwarderScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(s).Build()
	ch := make(chan controller.AuditForwarderEvent, 10)

	c := &controller.AuditForwarderController{
		Client:        fakeClient,
		EventCh:       ch,
		ClusterID:     "ccs-dev",
		FlushInterval: 30 * time.Millisecond,
		BatchSize:     100,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go func() { _ = c.Start(ctx) }()

	time.Sleep(200 * time.Millisecond)

	cmList := &corev1.ConfigMapList{}
	if err := fakeClient.List(ctx, cmList); err != nil {
		t.Fatalf("List ConfigMaps: %v", err)
	}
	if len(cmList.Items) != 0 {
		t.Errorf("expected 0 ConfigMaps for empty flush, got %d", len(cmList.Items))
	}
}

// TestAuditForwarder_StagingAreaLabel verifies the staging namespace and label
// on every written ConfigMap.
func TestAuditForwarder_StagingAreaLabel(t *testing.T) {
	s := buildForwarderScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(s).Build()
	ch := make(chan controller.AuditForwarderEvent, 10)

	c := &controller.AuditForwarderController{
		Client:        fakeClient,
		EventCh:       ch,
		ClusterID:     "ccs-dev",
		FlushInterval: 30 * time.Millisecond,
		BatchSize:     1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() { _ = c.Start(ctx) }()

	ch <- controller.AuditForwarderEvent{Subject: "x"}
	ch <- controller.AuditForwarderEvent{Subject: "y"}

	time.Sleep(200 * time.Millisecond)

	cmList := &corev1.ConfigMapList{}
	if err := fakeClient.List(ctx, cmList); err != nil {
		t.Fatalf("List ConfigMaps: %v", err)
	}
	if len(cmList.Items) < 2 {
		t.Fatalf("expected at least 2 ConfigMaps (batch-size=1), got %d", len(cmList.Items))
	}
	for _, cm := range cmList.Items {
		if cm.Labels[controller.AuditForwarderLabelKey] != controller.AuditForwarderLabelValue {
			t.Errorf("ConfigMap %s missing audit-batch=true label", cm.Name)
		}
		if cm.Namespace != controller.AuditForwarderStagingNamespace {
			t.Errorf("ConfigMap %s has wrong namespace %q (want %q)",
				cm.Name, cm.Namespace, controller.AuditForwarderStagingNamespace)
		}
	}
}
