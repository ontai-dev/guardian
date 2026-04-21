package controller

import (
	"context"
	"time"

	"github.com/ontai-dev/guardian/internal/database"
	"github.com/ontai-dev/seam-core/pkg/lineage"
)

// writeAudit writes event to aw if aw is non-nil. Failures are discarded --
// audit is best-effort and must never block reconciliation.
func writeAudit(ctx context.Context, aw database.AuditWriter, event database.AuditEvent) {
	if aw == nil {
		return
	}
	_ = aw.Write(ctx, event)
}

// auditSeq returns a monotonic sequence number proxy using UnixNano.
// This is a sufficient proxy until a proper per-cluster sequence generator
// is implemented. guardian-schema.md §16.
func auditSeq() int64 {
	return time.Now().UnixNano()
}

// lineageRef builds a LineageIndexRef for a governed-object audit event.
// kind and name are the root declaration kind/name; namespace is the ILI namespace.
// guardian-schema.md §17.
func lineageRef(kind, name, namespace string) *database.LineageIndexRef {
	return &database.LineageIndexRef{
		Name:      lineage.IndexName(kind, name),
		Namespace: namespace,
	}
}
