// Package database — AuditWriter interface and implementations.
//
// AuditWriter is the single channel through which Guardian reconcilers and
// webhook handlers write operational audit events to the management cluster's
// CNPG audit_events table. Three implementations cover the three operational
// states:
//
//   - SQLAuditWriter: production path, writes via SQLAuditStore.InsertEvent.
//   - NoopAuditWriter: test and tenant-role path, discards all events.
//   - LazyAuditWriter: management startup path, silently drops events while
//     CNPG is not yet connected (degraded mode), then writes once Set is called.
//
// guardian-schema.md §16.
package database

import (
	"context"
	"errors"
	"log/slog"
	"sync"
)

// AuditWriter is the interface through which Guardian components write audit
// events. A nil-safe helper in the controller package (writeAudit) allows
// callers to pass a nil AuditWriter and treat it as a no-op.
type AuditWriter interface {
	// Write inserts event into the audit store. Implementations must be safe
	// for concurrent use. Failures should be treated as non-fatal by callers
	// — audit is best-effort and must not block reconciliation.
	Write(ctx context.Context, event AuditEvent) error
}

// ---------------------------------------------------------------------------
// SQLAuditWriter
// ---------------------------------------------------------------------------

// SQLAuditWriter writes audit events directly to the CNPG-backed audit_events
// table via a SQLAuditStore. This is the production implementation used when
// CNPG is operational.
type SQLAuditWriter struct {
	store *SQLAuditStore
}

// NewSQLAuditWriter returns an SQLAuditWriter backed by store.
func NewSQLAuditWriter(store *SQLAuditStore) *SQLAuditWriter {
	return &SQLAuditWriter{store: store}
}

// Write inserts event into the audit_events table.
func (w *SQLAuditWriter) Write(ctx context.Context, event AuditEvent) error {
	return w.store.InsertEvent(ctx, event)
}

// ---------------------------------------------------------------------------
// NoopAuditWriter
// ---------------------------------------------------------------------------

// NoopAuditWriter discards all events. It is used in unit tests and in
// role=tenant deployments where Guardian has no CNPG dependency.
type NoopAuditWriter struct{}

// Write discards event and returns nil.
func (NoopAuditWriter) Write(_ context.Context, _ AuditEvent) error { return nil }

// ---------------------------------------------------------------------------
// LazyAuditWriter
// ---------------------------------------------------------------------------

// maxPendingAuditEvents is the maximum number of events buffered in the
// LazyAuditWriter ring buffer while CNPG is not yet available.
const maxPendingAuditEvents = 100

// LazyAuditWriter wraps a LazyAuditDatabase and provides degraded-mode audit
// writing with a bounded in-memory ring buffer.
//
// When the database is not yet connected (ErrDatabaseNotReady), events are
// buffered in a ring buffer of up to maxPendingAuditEvents entries. Oldest
// events are evicted when the buffer is full. Once cnpgStartupRunnable calls
// LazyAuditDatabase.Set, the next Write call attempts to flush all buffered
// events before writing the new one.
//
// Thread-safe via an internal mutex. guardian-schema.md §3 Step 1, §16.
type LazyAuditWriter struct {
	db      *LazyAuditDatabase
	mu      sync.Mutex
	pending []AuditEvent
}

// NewLazyAuditWriter returns a LazyAuditWriter backed by db.
func NewLazyAuditWriter(db *LazyAuditDatabase) *LazyAuditWriter {
	return &LazyAuditWriter{db: db}
}

// Write inserts event via the lazy database.
//
// If the database is not yet ready:
//   - The event is added to the in-memory ring buffer (evicting the oldest if full).
//   - nil is returned so callers are not interrupted.
//
// If the database is ready and there are buffered events:
//   - A flush attempt is made first. Events that still fail with ErrDatabaseNotReady
//     are kept; events that fail with other errors are logged and dropped.
//   - The new event is then written normally.
//
// All non-transient errors on the current event are propagated to the caller.
func (w *LazyAuditWriter) Write(ctx context.Context, event AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Attempt to flush any buffered events now that the database may be ready.
	if len(w.pending) > 0 {
		remaining := w.pending[:0]
		for _, pe := range w.pending {
			if err := w.db.InsertEvent(ctx, pe); err != nil {
				if errors.Is(err, ErrDatabaseNotReady) {
					remaining = append(remaining, pe)
				} else {
					slog.Default().Warn("dropping buffered audit event: non-transient insert error",
						"action", pe.Action, "resource", pe.Resource, "error", err)
				}
			}
		}
		w.pending = remaining
	}

	// Write the current event.
	if err := w.db.InsertEvent(ctx, event); err != nil {
		if errors.Is(err, ErrDatabaseNotReady) {
			// Buffer the event; evict oldest if the ring is full.
			if len(w.pending) >= maxPendingAuditEvents {
				slog.Default().Warn("audit ring buffer full — evicting oldest event",
					"dropped_action", w.pending[0].Action,
					"dropped_resource", w.pending[0].Resource)
				w.pending = w.pending[1:]
			}
			w.pending = append(w.pending, event)
			return nil
		}
		return err
	}
	return nil
}
