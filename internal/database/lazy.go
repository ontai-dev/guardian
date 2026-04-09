package database

import (
	"context"
	"fmt"
	"sync"
)

// ErrDatabaseNotReady is returned by LazyAuditDatabase when the real CNPG
// connection has not yet been established. The AuditSinkReconciler treats this
// as a transient error and requeues the batch ConfigMap for retry.
// guardian-schema.md §3 Step 1.
var ErrDatabaseNotReady = fmt.Errorf("CNPG database not yet available")

// LazyAuditDatabase is an AuditDatabase that defers its real connection until
// Set is called. It is constructed before controller registration in main and
// passed to AuditSinkReconciler so the reconciler always holds a non-nil DB.
// Once the cnpgStartupRunnable establishes the CNPG connection it calls Set,
// making all forwarding calls live.
//
// Before Set: EventExists and InsertEvent return ErrDatabaseNotReady, which
// causes the reconciler to return an error and requeue without deleting the
// batch ConfigMap. After Set: all calls are forwarded to the real AuditDatabase.
// Thread-safe via a read-write mutex.
//
// guardian-schema.md §3 Step 1, §16.
type LazyAuditDatabase struct {
	mu   sync.RWMutex
	real AuditDatabase
}

// NewLazyAuditDatabase returns an unready LazyAuditDatabase. Call Set once the
// real database connection is available.
func NewLazyAuditDatabase() *LazyAuditDatabase {
	return &LazyAuditDatabase{}
}

// Set stores the real AuditDatabase. Safe to call from a concurrent goroutine.
// After Set returns, all subsequent EventExists and InsertEvent calls are
// forwarded to the real database.
func (l *LazyAuditDatabase) Set(db AuditDatabase) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.real = db
}

// EventExists forwards to the real database, or returns ErrDatabaseNotReady if
// Set has not yet been called.
func (l *LazyAuditDatabase) EventExists(ctx context.Context, clusterID string, sequenceNumber int64) (bool, error) {
	l.mu.RLock()
	db := l.real
	l.mu.RUnlock()
	if db == nil {
		return false, ErrDatabaseNotReady
	}
	return db.EventExists(ctx, clusterID, sequenceNumber)
}

// InsertEvent forwards to the real database, or returns ErrDatabaseNotReady if
// Set has not yet been called.
func (l *LazyAuditDatabase) InsertEvent(ctx context.Context, event AuditEvent) error {
	l.mu.RLock()
	db := l.real
	l.mu.RUnlock()
	if db == nil {
		return ErrDatabaseNotReady
	}
	return db.InsertEvent(ctx, event)
}
