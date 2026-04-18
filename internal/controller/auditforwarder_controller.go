package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// AuditForwarderLabelKey is the label applied to ConfigMaps written to the
// staging area. Conductor's federation channel reads ConfigMaps with this label.
// conductor-schema.md §18, guardian-schema.md §15.
const AuditForwarderLabelKey = "seam.ontai.dev/audit-batch"

// AuditForwarderLabelValue is the required value for the audit-batch label.
const AuditForwarderLabelValue = "true"

// AuditForwarderStagingNamespace is the namespace where audit batch ConfigMaps
// are written on tenant clusters. Conductor's federation channel reads from here.
const AuditForwarderStagingNamespace = "ont-system"

// DefaultForwarderFlushInterval is the default batch flush interval.
const DefaultForwarderFlushInterval = 30 * time.Second

// DefaultForwarderBatchSize is the default number of events per batch before
// flushing, regardless of elapsed time.
const DefaultForwarderBatchSize = 100

// AuditForwarderController collects audit events produced by Guardian's own
// policy evaluation decisions and batches them for Conductor to forward to the
// management cluster's AuditSink via the federation channel.
//
// Role: tenant only. guardian-schema.md §15.
//
// Events are read from an in-memory channel written by the webhook decision path.
// Batches are written to ConfigMaps in ont-system with label
// seam.ontai.dev/audit-batch=true and the originating cluster ID in annotations.
// Conductor's federation channel (conductor-schema.md §18) picks up and transports
// these ConfigMaps to the management Guardian AuditSinkReconciler.
type AuditForwarderController struct {
	// Client is the controller-runtime client for Kubernetes API access.
	Client client.Client

	// Scheme is the runtime scheme used for object type registration.
	Scheme *runtime.Scheme

	// Recorder is the Kubernetes event recorder.
	Recorder record.EventRecorder

	// EventCh is the in-memory channel that the webhook decision path writes
	// AuditForwarderEvent values to. Must be set before Start is called.
	EventCh <-chan AuditForwarderEvent

	// ClusterID identifies this tenant cluster in the audit record.
	ClusterID string

	// FlushInterval is the maximum time between batch flushes. Defaults to
	// DefaultForwarderFlushInterval if zero.
	FlushInterval time.Duration

	// BatchSize is the maximum number of events per batch. Defaults to
	// DefaultForwarderBatchSize if zero.
	BatchSize int

	// mu guards pending.
	mu      sync.Mutex
	pending []AuditForwarderEvent
	seq     int64
}

// AuditForwarderEvent is a single audit event produced by the webhook decision path.
type AuditForwarderEvent struct {
	Subject       string
	Action        string
	Resource      string
	Decision      string
	MatchedPolicy string
}

// Start begins the flush loop. It is called by controller-runtime as a Runnable.
func (c *AuditForwarderController) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("audit-forwarder")
	flushInterval := c.FlushInterval
	if flushInterval == 0 {
		flushInterval = DefaultForwarderFlushInterval
	}
	batchSize := c.BatchSize
	if batchSize == 0 {
		batchSize = DefaultForwarderBatchSize
	}

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case ev, ok := <-c.EventCh:
			if !ok {
				return nil
			}
			c.mu.Lock()
			c.pending = append(c.pending, ev)
			shouldFlush := len(c.pending) >= batchSize
			c.mu.Unlock()
			if shouldFlush {
				if err := c.flush(ctx); err != nil {
					logger.Error(err, "flush on size threshold failed")
				}
			}

		case <-ticker.C:
			if err := c.flush(ctx); err != nil {
				logger.Error(err, "flush on interval failed")
			}
		}
	}
}

// flush writes the current pending batch as a ConfigMap in the staging area.
func (c *AuditForwarderController) flush(ctx context.Context) error {
	c.mu.Lock()
	if len(c.pending) == 0 {
		c.mu.Unlock()
		return nil
	}
	batch := c.pending
	c.pending = nil
	c.seq++
	seq := c.seq
	c.mu.Unlock()

	logger := log.FromContext(ctx).WithName("audit-forwarder")
	logger.Info("flushing audit batch", "events", len(batch), "sequence", seq)

	// Serialize events to the wire format expected by AuditSinkReconciler.
	type wireEvent struct {
		SequenceNumber int64  `json:"sequenceNumber"`
		Subject        string `json:"subject"`
		Action         string `json:"action"`
		Resource       string `json:"resource"`
		Decision       string `json:"decision"`
		MatchedPolicy  string `json:"matchedPolicy"`
	}
	wire := make([]wireEvent, len(batch))
	for i, e := range batch {
		wire[i] = wireEvent{
			SequenceNumber: seq*int64(len(batch)) + int64(i) + 1,
			Subject:        e.Subject,
			Action:         e.Action,
			Resource:       e.Resource,
			Decision:       e.Decision,
			MatchedPolicy:  e.MatchedPolicy,
		}
	}
	eventsJSON, err := json.Marshal(wire)
	if err != nil {
		return fmt.Errorf("marshal audit batch: %w", err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "audit-batch-",
			Namespace:    AuditForwarderStagingNamespace,
			Labels: map[string]string{
				AuditForwarderLabelKey: AuditForwarderLabelValue,
			},
			Annotations: map[string]string{
				"seam.ontai.dev/cluster-id":        c.ClusterID,
				"seam.ontai.dev/batch-sequence":    fmt.Sprint(seq),
				"seam.ontai.dev/audit-event-count": fmt.Sprint(len(batch)),
			},
		},
		Data: map[string]string{
			"events": string(eventsJSON),
		},
	}
	return c.Client.Create(ctx, cm)
}

// SetupWithManager registers AuditForwarderController as a Runnable (not a
// reconciler — it is event-driven by the in-memory channel, not by watch events).
func (c *AuditForwarderController) SetupWithManager(mgr ctrl.Manager) error {
	return mgr.Add(c)
}
