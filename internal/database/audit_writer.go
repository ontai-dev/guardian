// Package database — AuditWriter interface and implementations.
//
// AuditWriter is the single channel through which Guardian reconcilers and
// webhook handlers write operational audit events to the management cluster's
// CNPG audit_events table. Three implementations cover the three operational
// states:
//
//   - SQLAuditWriter: production path, writes via SQLAuditStore.InsertEvent.
//   - NoopAuditWriter: test and tenant-role path, discards all events.
//   - LazyAuditWriter: management startup path, logs a warning and drops events
//     while CNPG is not yet connected (degraded mode). No in-memory buffering.
//
// guardian-schema.md §16.
package database

import (
	"context"
	"errors"
	"log/slog"
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

// LazyAuditWriter wraps a LazyAuditDatabase and provides degraded-mode audit
// writing. When the database is not yet connected (ErrDatabaseNotReady), the
// event is logged as a structured warning and silently dropped so callers are
// not interrupted. No in-memory buffering is used — simplicity is preferred
// over completeness for pre-CNPG events.
//
// Once cnpgStartupRunnable calls LazyAuditDatabase.Set, subsequent Write calls
// are forwarded to the real database without delay.
//
// guardian-schema.md §3 Step 1, §16.
type LazyAuditWriter struct {
	db *LazyAuditDatabase
}

// NewLazyAuditWriter returns a LazyAuditWriter backed by db.
func NewLazyAuditWriter(db *LazyAuditDatabase) *LazyAuditWriter {
	return &LazyAuditWriter{db: db}
}

// Write inserts event via the lazy database.
//
// When the database is not yet ready, logs a structured warning and returns nil
// so callers are not interrupted. All other errors are propagated.
func (w *LazyAuditWriter) Write(ctx context.Context, event AuditEvent) error {
	if err := w.db.InsertEvent(ctx, event); err != nil {
		if errors.Is(err, ErrDatabaseNotReady) {
			slog.Default().Warn("audit event dropped — database not ready",
				"action", event.Action,
				"resource", event.Resource,
				"subject", event.Subject)
			return nil
		}
		return err
	}
	return nil
}
