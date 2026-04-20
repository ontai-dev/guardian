// Package database_test covers the MigrationRunner and CNPG startup logic.
//
// Tests use a mock DB implementation — no real CNPG connection is required.
// The mock tracks SQL statements executed against it so assertions can verify
// that migrations are applied in order and recorded correctly.
//
// guardian-schema.md §3 Step 1, §16.
package database_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"strings"
	"testing"

	"github.com/ontai-dev/guardian/internal/database"
)

type mockResult struct{}

func (mockResult) LastInsertId() (int64, error) { return 0, nil }
func (mockResult) RowsAffected() (int64, error) { return 1, nil }

// ── MigrationRunner with in-process driver ───────────────────────────────────
// Rather than using mockDB.QueryRowContext (which can't return *sql.Row without
// a driver), the migration tests use an in-memory SQLite database via the
// testDB helper below if a driver is available, or verify migration logic
// through the mock ExecContext calls when a SQL driver is unavailable.
//
// Since adding SQLite is out of scope for this session, we verify MigrationRunner
// logic through a stub DB that captures queries and simulates COUNT responses
// using a channel-based approach.

// stubDB is a test-friendly implementation of database.DB that simulates
// a PostgreSQL database for MigrationRunner tests. It uses a simulated
// schema_migrations table tracked in memory.
type stubDB struct {
	// migrations tracks applied migration IDs, simulating schema_migrations.
	migrations map[int]bool

	// execCalls records all ExecContext calls in order.
	execCalls []execCall

	// forceMigrationError causes Run to fail on a specific migration ID.
	forceMigrationError int
}

type execCall struct {
	query string
	args  []any
}

func newStubDB() *stubDB {
	return &stubDB{migrations: make(map[int]bool)}
}

// QueryRowContext simulates "SELECT COUNT(*) FROM schema_migrations WHERE id = $1".
// It returns a real *sql.Row by opening an in-memory database that can actually
// scan an integer. We achieve this by using sql.OpenDB with a custom driver that
// returns a hardcoded row. Since that is complex, we instead embed an integer
// directly using a scannable row.
func (s *stubDB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	// We simulate two query patterns used by MigrationRunner:
	//   SELECT COUNT(*) FROM schema_migrations WHERE id = $1  -> migration check
	//   SELECT COUNT(*) FROM schema_migrations                 -> table check (not used by runner)
	//
	// We implement a zero-dependency approach: use a connector backed by the
	// stdlib "register driver" mechanism with our own fake driver.
	// See fakeDriverDB below.
	count := 0
	if strings.Contains(query, "WHERE id = $1") && len(args) > 0 {
		if id, ok := args[0].(int); ok && s.migrations[id] {
			count = 1
		}
	}
	return newFakeRow(count)
}

func (s *stubDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if s.forceMigrationError > 0 {
		// Fail on the DDL for the forced migration ID.
		if strings.Contains(query, "CREATE TABLE") || strings.Contains(query, "audit_events") ||
			strings.Contains(query, "permission_cache") || strings.Contains(query, "identity_resolution_log") {
			for _, m := range s.execCalls {
				_ = m
			}
			// Determine current migration being applied by counting non-schema-migrations execCalls.
			nonMeta := 0
			for _, ec := range s.execCalls {
				if !strings.Contains(ec.query, "schema_migrations") {
					nonMeta++
				}
			}
			if nonMeta >= s.forceMigrationError-1 {
				s.execCalls = append(s.execCalls, execCall{query: query, args: args})
				return nil, fmt.Errorf("forced migration error for migration %d", s.forceMigrationError)
			}
		}
	}

	s.execCalls = append(s.execCalls, execCall{query: query, args: args})

	// Track migration recording.
	if strings.Contains(query, "INSERT INTO schema_migrations") && len(args) > 0 {
		if id, ok := args[0].(int); ok {
			s.migrations[id] = true
		}
	}
	return mockResult{}, nil
}

func (s *stubDB) PingContext(ctx context.Context) error { return nil }

// ── Fake row for QueryRowContext ──────────────────────────────────────────────

// fakeRow implements the Row.Scan contract by encoding a pre-computed integer.
// We open a real in-memory database with a single SELECT to produce a *sql.Row.
// This uses the "github.com/mattn/go-sqlite3" driver if available — but since
// we cannot guarantee it, we use an alternative: the driver-less scan approach
// via a registered test driver.
var fakeDriverRegistered bool

func newFakeRow(count int) *sql.Row {
	// Use an in-memory source we can synthesise. Since database/sql.Row cannot
	// be constructed directly, we register a minimal test driver that serves
	// a single integer row.
	if !fakeDriverRegistered {
		sql.Register("fake", &fakeDriver{})
		fakeDriverRegistered = true
	}
	db, _ := sql.Open("fake", fmt.Sprintf("count=%d", count))
	return db.QueryRow("SELECT ?", count)
}

// fakeDriver is a minimal database/sql driver that serves one integer row.
type fakeDriver struct{}

func (f *fakeDriver) Open(name string) (driver.Conn, error) {
	// Parse "count=N" from name.
	var count int
	if _, err := fmt.Sscanf(name, "count=%d", &count); err != nil {
		return nil, fmt.Errorf("fakeDriver: parse count: %w", err)
	}
	return &fakeConn{count: count}, nil
}

type fakeConn struct {
	count int
}

func (c *fakeConn) Prepare(query string) (driver.Stmt, error) {
	return &fakeStmt{count: c.count}, nil
}

func (c *fakeConn) Close() error { return nil }

func (c *fakeConn) Begin() (driver.Tx, error) {
	return nil, fmt.Errorf("transactions not supported")
}

type fakeStmt struct{ count int }

func (s *fakeStmt) Close() error { return nil }

func (s *fakeStmt) NumInput() int { return 1 }

func (s *fakeStmt) Exec(args []driver.Value) (driver.Result, error) {
	return nil, fmt.Errorf("exec not supported")
}

func (s *fakeStmt) Query(args []driver.Value) (driver.Rows, error) { //nolint:govet
	return &fakeRows{count: s.count, done: false}, nil
}

type fakeRows struct {
	count int
	done  bool
}

func (r *fakeRows) Columns() []string { return []string{"count"} }

func (r *fakeRows) Close() error { return nil }

func (r *fakeRows) Next(dest []driver.Value) error {
	if r.done {
		return fmt.Errorf("no more rows")
	}
	r.done = true
	dest[0] = int64(r.count)
	return nil
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// We need to import database/sql/driver for the fakeDriver.
// Let's use a simpler approach: instead of implementing a sql.Driver,
// test the MigrationRunner logic by replacing QueryRowContext with a channel-based stub.
//
// Actually, the cleanest approach for testing MigrationRunner without a real driver
// is to test it with a real in-memory database. The stdlib provides no in-memory
// database without an external driver. Since the directive says "no real CNPG",
// we test at a higher level: we verify migration idempotency and ordering by
// constructing a custom DB implementation that counts query calls.

// Let's simplify: use a simpleDB that uses an embedded map to simulate migrations.

// simpleDB implements database.DB using pure Go maps; no real SQL driver needed.
// QueryRowContext returns a *sql.Row by using the "fake" driver registered above.
type simpleDB struct {
	applied map[int]bool
	execs   []string
}

func newSimpleDB() *simpleDB {
	return &simpleDB{applied: make(map[int]bool)}
}

func (d *simpleDB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	count := 0
	if strings.Contains(query, "WHERE id = $1") && len(args) > 0 {
		if id, ok := args[0].(int); ok && d.applied[id] {
			count = 1
		}
	}
	return newFakeRow(count)
}

func (d *simpleDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	d.execs = append(d.execs, query)
	if strings.Contains(query, "INSERT INTO schema_migrations") && len(args) > 0 {
		if id, ok := args[0].(int); ok {
			d.applied[id] = true
		}
	}
	return mockResult{}, nil
}

func (d *simpleDB) PingContext(ctx context.Context) error { return nil }

// TestMigrationRunner_AppliesAllMigrations verifies that a fresh database receives
// all five migrations and the schema_migrations table creation DDL.
func TestMigrationRunner_AppliesAllMigrations(t *testing.T) {
	db := newSimpleDB()
	runner := database.NewMigrationRunner(db)

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// All five migration IDs must be recorded.
	for _, id := range []int{1, 2, 3, 4, 5} {
		if !db.applied[id] {
			t.Errorf("migration %d not recorded in applied map", id)
		}
	}
}

// TestMigrationRunner_Idempotent verifies that running twice does not re-apply
// migrations already recorded.
func TestMigrationRunner_Idempotent(t *testing.T) {
	db := newSimpleDB()
	runner := database.NewMigrationRunner(db)

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("first Run returned error: %v", err)
	}
	firstExecCount := len(db.execs)

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("second Run returned error: %v", err)
	}
	secondExecCount := len(db.execs)

	// Second run should only re-create the schema_migrations table (idempotent DDL)
	// and query each migration's applied status. No new migration DDL should execute.
	// The only new ExecContext call on the second run is the CREATE TABLE IF NOT EXISTS.
	extraExecs := secondExecCount - firstExecCount
	if extraExecs > 1 {
		t.Errorf("second Run performed %d extra ExecContext calls (expected ≤1 for idempotent create-if-not-exists)", extraExecs)
	}
}

// TestMigrationRunner_AppliesInOrder verifies that the migration DDL statements
// contain the expected table/index names in order.
func TestMigrationRunner_AppliesInOrder(t *testing.T) {
	db := newSimpleDB()
	runner := database.NewMigrationRunner(db)

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// Find the exec calls containing each migration's distinctive keyword, in order.
	// Migration 5 uses CREATE UNIQUE INDEX; the keyword "idx_audit_events_cluster_seq"
	// uniquely identifies it.
	markers := []string{
		"audit_events",
		"permission_cache",
		"identity_resolution_log",
		"permission_snapshot_audit",
		"idx_audit_events_cluster_seq",
	}
	positions := make([]int, len(markers))
	for i, marker := range markers {
		for j, exec := range db.execs {
			if strings.Contains(exec, marker) {
				positions[i] = j
				break
			}
		}
	}

	for i := 1; i < len(positions); i++ {
		if positions[i] <= positions[i-1] {
			t.Errorf("migration %d (%s) applied before migration %d (%s)",
				i+1, markers[i], i, markers[i-1])
		}
	}
}

// TestMigrationRunner_SkipsAlreadyApplied verifies that migrations already
// recorded in schema_migrations are not re-executed.
func TestMigrationRunner_SkipsAlreadyApplied(t *testing.T) {
	db := newSimpleDB()
	// Pre-seed migrations 1 and 2 as already applied.
	db.applied[1] = true
	db.applied[2] = true

	runner := database.NewMigrationRunner(db)
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// Migrations 1 and 2 must not re-appear; migrations 3, 4, 5 must be applied.
	hasAuditEvents := false
	hasPermissionCache := false
	hasIdentityLog := false
	hasSnapshotAudit := false
	hasUniqueIndex := false
	for _, exec := range db.execs {
		if strings.Contains(exec, "audit_events") && strings.Contains(exec, "CREATE TABLE") {
			hasAuditEvents = true
		}
		if strings.Contains(exec, "permission_cache") {
			hasPermissionCache = true
		}
		if strings.Contains(exec, "identity_resolution_log") {
			hasIdentityLog = true
		}
		if strings.Contains(exec, "permission_snapshot_audit") {
			hasSnapshotAudit = true
		}
		if strings.Contains(exec, "idx_audit_events_cluster_seq") {
			hasUniqueIndex = true
		}
	}

	if hasAuditEvents {
		t.Error("migration 1 (audit_events) was re-applied despite being already recorded")
	}
	if hasPermissionCache {
		t.Error("migration 2 (permission_cache) was re-applied despite being already recorded")
	}
	if !hasIdentityLog {
		t.Error("migration 3 (identity_resolution_log) was not applied")
	}
	if !hasSnapshotAudit {
		t.Error("migration 4 (permission_snapshot_audit) was not applied")
	}
	if !hasUniqueIndex {
		t.Error("migration 5 (idx_audit_events_cluster_seq) was not applied")
	}
}

// TestMigrationRunner_Migration001_AuditEventsColumns verifies that the DDL executed
// for migration 001 contains all columns required by InsertEvent and EventExists.
// guardian-schema.md §3 Step 1.
func TestMigrationRunner_Migration001_AuditEventsColumns(t *testing.T) {
	db := newSimpleDB()
	runner := database.NewMigrationRunner(db)
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	var auditSQL string
	for _, exec := range db.execs {
		if strings.Contains(exec, "audit_events") && strings.Contains(exec, "CREATE") {
			auditSQL = exec
			break
		}
	}
	if auditSQL == "" {
		t.Fatal("audit_events CREATE TABLE statement not found in exec calls")
	}

	required := []string{
		"cluster_id", "subject", "action", "resource",
		"decision", "matched_policy", "sequence_number", "timestamp",
	}
	for _, col := range required {
		if !strings.Contains(auditSQL, col) {
			t.Errorf("audit_events migration DDL missing required column %q", col)
		}
	}
}

// TestMigrationRunner_Migration002_PermissionCacheColumns verifies that the DDL for
// migration 002 contains all columns required by the permission_cache table.
func TestMigrationRunner_Migration002_PermissionCacheColumns(t *testing.T) {
	db := newSimpleDB()
	runner := database.NewMigrationRunner(db)
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	var cacheSQL string
	for _, exec := range db.execs {
		if strings.Contains(exec, "permission_cache") && strings.Contains(exec, "CREATE") {
			cacheSQL = exec
			break
		}
	}
	if cacheSQL == "" {
		t.Fatal("permission_cache CREATE TABLE statement not found in exec calls")
	}

	required := []string{"subject", "action", "resource", "result", "expires_at"}
	for _, col := range required {
		if !strings.Contains(cacheSQL, col) {
			t.Errorf("permission_cache migration DDL missing required column %q", col)
		}
	}
}

// TestMigrationRunner_Migration003_IdentityResolutionLogColumns verifies that the DDL
// for migration 003 contains all columns required by the identity_resolution_log table.
func TestMigrationRunner_Migration003_IdentityResolutionLogColumns(t *testing.T) {
	db := newSimpleDB()
	runner := database.NewMigrationRunner(db)
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	var logSQL string
	for _, exec := range db.execs {
		if strings.Contains(exec, "identity_resolution_log") && strings.Contains(exec, "CREATE") {
			logSQL = exec
			break
		}
	}
	if logSQL == "" {
		t.Fatal("identity_resolution_log CREATE TABLE statement not found in exec calls")
	}

	required := []string{"subject", "provider_name", "resolved_profile", "resolved_at"}
	for _, col := range required {
		if !strings.Contains(logSQL, col) {
			t.Errorf("identity_resolution_log migration DDL missing required column %q", col)
		}
	}
}

// TestMigrationRunner_Migration004_PermissionSnapshotAuditColumns verifies that the DDL
// for migration 004 contains all columns required by the permission_snapshot_audit table.
// guardian-schema.md §7, INV-026.
func TestMigrationRunner_Migration004_PermissionSnapshotAuditColumns(t *testing.T) {
	db := newSimpleDB()
	runner := database.NewMigrationRunner(db)
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	var snapshotSQL string
	for _, exec := range db.execs {
		if strings.Contains(exec, "permission_snapshot_audit") && strings.Contains(exec, "CREATE") {
			snapshotSQL = exec
			break
		}
	}
	if snapshotSQL == "" {
		t.Fatal("permission_snapshot_audit CREATE TABLE statement not found in exec calls")
	}

	required := []string{
		"snapshot_name", "namespace", "target_cluster", "snapshot_hash",
		"generated_at", "signed_by", "signed_at", "delivered_at", "receipt_name",
	}
	for _, col := range required {
		if !strings.Contains(snapshotSQL, col) {
			t.Errorf("permission_snapshot_audit migration DDL missing required column %q", col)
		}
	}
}

// TestMigrationRunner_Migration005_UniqueIndexPresent verifies that migration 005 emits a
// CREATE UNIQUE INDEX statement targeting audit_events(cluster_id, sequence_number).
func TestMigrationRunner_Migration005_UniqueIndexPresent(t *testing.T) {
	db := newSimpleDB()
	runner := database.NewMigrationRunner(db)
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	var indexSQL string
	for _, exec := range db.execs {
		if strings.Contains(exec, "idx_audit_events_cluster_seq") {
			indexSQL = exec
			break
		}
	}
	if indexSQL == "" {
		t.Fatal("idx_audit_events_cluster_seq index statement not found in exec calls")
	}
	if !strings.Contains(indexSQL, "CREATE UNIQUE INDEX") {
		t.Errorf("migration 005 DDL is not a CREATE UNIQUE INDEX: %s", indexSQL)
	}
	if !strings.Contains(indexSQL, "audit_events") {
		t.Errorf("migration 005 index does not target audit_events table: %s", indexSQL)
	}
	if !strings.Contains(indexSQL, "cluster_id") || !strings.Contains(indexSQL, "sequence_number") {
		t.Errorf("migration 005 index missing cluster_id or sequence_number columns: %s", indexSQL)
	}
}

// TestMigrationRunner_HaltsOnFailureBeforeNextMigration verifies that if migration N
// fails, migration N+1 is not applied — the runner halts at the first failure.
// Uses forceMigrationError=2 which causes permission_cache DDL to fail after
// audit_events has already been successfully applied.
func TestMigrationRunner_HaltsOnFailureBeforeNextMigration(t *testing.T) {
	db := newStubDB()
	db.forceMigrationError = 2 // fail migration 2 (permission_cache)
	runner := database.NewMigrationRunner(db)

	err := runner.Run(context.Background())
	if err == nil {
		t.Fatal("expected Run to return an error when migration 2 fails")
	}

	// Migration 1 should have been applied (it precedes the failure).
	if !db.migrations[1] {
		t.Error("expected migration 1 to be recorded (applied before failure)")
	}
	// Migration 2 DDL failed — its recording INSERT should never have executed.
	if db.migrations[2] {
		t.Error("migration 2 was recorded despite its DDL failing")
	}
	// Migration 3 should never have been attempted.
	if db.migrations[3] {
		t.Error("migration 3 was applied despite migration 2 failing (halt violated)")
	}
}

// TestConnConfig_DSN verifies DSN transformations: pooler-to-rw host rewrite and
// sslmode=require insertion.
func TestConnConfig_DSN(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{
			name:     "no sslmode — appends sslmode=require",
			uri:      "postgresql://guardian:secret@cnpg-rw.seam-system.svc:5432/guardian",
			expected: "postgresql://guardian:secret@cnpg-rw.seam-system.svc:5432/guardian?sslmode=require",
		},
		{
			name:     "existing query param — appends &sslmode=require",
			uri:      "postgresql://guardian:secret@cnpg-rw.seam-system.svc:5432/guardian?connect_timeout=10",
			expected: "postgresql://guardian:secret@cnpg-rw.seam-system.svc:5432/guardian?connect_timeout=10&sslmode=require",
		},
		{
			name:     "sslmode already present — left unchanged",
			uri:      "postgresql://guardian:secret@cnpg-rw.seam-system.svc:5432/guardian?sslmode=verify-full",
			expected: "postgresql://guardian:secret@cnpg-rw.seam-system.svc:5432/guardian?sslmode=verify-full",
		},
		{
			// Pooler URI from CNPG app Secret: PgBouncer caches md5 hashes and
			// causes "password authentication failed" on guardian pod restarts.
			// DSN rewrites the host to the rw service to bypass the pooler.
			name:     "pooler host — rewritten to rw service",
			uri:      "postgresql://guardian:secret@guardian-cnpg-pooler.seam-system.svc:5432/guardian",
			expected: "postgresql://guardian:secret@guardian-cnpg-rw.seam-system.svc:5432/guardian?sslmode=require",
		},
		{
			name:     "pooler host with existing sslmode — host rewritten, sslmode preserved",
			uri:      "postgresql://guardian:secret@guardian-cnpg-pooler.seam-system.svc:5432/guardian?sslmode=require",
			expected: "postgresql://guardian:secret@guardian-cnpg-rw.seam-system.svc:5432/guardian?sslmode=require",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := database.ConnConfig{URI: tc.uri}
			dsn := cfg.DSN()
			if dsn != tc.expected {
				t.Errorf("DSN mismatch\ngot:  %s\nwant: %s", dsn, tc.expected)
			}
		})
	}
}
