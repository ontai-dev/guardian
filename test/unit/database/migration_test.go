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

// mockDB implements database.DB using in-memory maps.
type mockDB struct {
	// appliedMigrations tracks which migration IDs have been recorded.
	appliedMigrations map[int]bool

	// execStatements records all SQL statements passed to ExecContext.
	execStatements []string

	// pingErr is returned by PingContext; nil means success.
	pingErr error

	// execErr is returned by ExecContext when set; nil means success.
	execErr error
}

func newMockDB() *mockDB {
	return &mockDB{appliedMigrations: make(map[int]bool)}
}

func (m *mockDB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	// Simulate COUNT(*) for schema_migrations existence check and migration applied check.
	// We can't return a real *sql.Row without a real database driver.
	// Use a thin wrapper approach: embed the answer in the mock.
	//
	// Since *sql.Row cannot be constructed without a driver, we use a workaround:
	// return a row that reads count=1 for known migrations, 0 otherwise.
	// This is done via a small SQLite/in-process trick but we don't have SQLite here.
	//
	// Instead, we implement QueryRowContext to handle the two query patterns used
	// by MigrationRunner by returning a specially-constructed *sql.Row.
	// The cleanest approach: return a *sql.Row from a real in-memory store.
	// We'll use database/sql with a test driver registered below.
	panic("use mockDBWithDriver instead of mockDB for MigrationRunner tests")
}

func (m *mockDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if m.execErr != nil {
		return nil, m.execErr
	}
	m.execStatements = append(m.execStatements, query)

	// Track migration recording: INSERT INTO schema_migrations with an id arg.
	if strings.Contains(query, "INSERT INTO schema_migrations") && len(args) > 0 {
		if id, ok := args[0].(int); ok {
			m.appliedMigrations[id] = true
		}
	}
	return mockResult{}, nil
}

func (m *mockDB) PingContext(ctx context.Context) error {
	return m.pingErr
}

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

// execQueriesContaining returns the subset of ExecContext calls whose SQL
// contains any of the given substrings.
func (s *stubDB) execQueriesContaining(substr string) []string {
	var out []string
	for _, ec := range s.execCalls {
		if strings.Contains(ec.query, substr) {
			out = append(out, ec.query)
		}
	}
	return out
}

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
	fmt.Sscanf(name, "count=%d", &count)
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
// all three migrations and the schema_migrations table creation DDL.
func TestMigrationRunner_AppliesAllMigrations(t *testing.T) {
	db := newSimpleDB()
	runner := database.NewMigrationRunner(db)

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// All three migration IDs must be recorded.
	for _, id := range []int{1, 2, 3} {
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
// contain the three expected table names in order.
func TestMigrationRunner_AppliesInOrder(t *testing.T) {
	db := newSimpleDB()
	runner := database.NewMigrationRunner(db)

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// Find the exec calls containing each table creation.
	tables := []string{"audit_events", "permission_cache", "identity_resolution_log"}
	positions := make([]int, len(tables))
	for i, table := range tables {
		for j, exec := range db.execs {
			if strings.Contains(exec, table) {
				positions[i] = j
				break
			}
		}
	}

	for i := 1; i < len(positions); i++ {
		if positions[i] <= positions[i-1] {
			t.Errorf("migration %d (%s) applied before migration %d (%s)",
				i+1, tables[i], i, tables[i-1])
		}
	}
}

// TestMigrationRunner_SkipsAlreadyApplied verifies that a migration already
// recorded in schema_migrations is not re-executed.
func TestMigrationRunner_SkipsAlreadyApplied(t *testing.T) {
	db := newSimpleDB()
	// Pre-seed migrations 1 and 2 as already applied.
	db.applied[1] = true
	db.applied[2] = true

	runner := database.NewMigrationRunner(db)
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// Only migration 3 should appear in exec calls (plus schema_migrations table ensure).
	hasAuditEvents := false
	hasPermissionCache := false
	hasIdentityLog := false
	for _, exec := range db.execs {
		if strings.Contains(exec, "audit_events") {
			hasAuditEvents = true
		}
		if strings.Contains(exec, "permission_cache") {
			hasPermissionCache = true
		}
		if strings.Contains(exec, "identity_resolution_log") {
			hasIdentityLog = true
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
}

// TestConnConfig_DSN verifies the DSN format.
func TestConnConfig_DSN(t *testing.T) {
	cfg := database.ConnConfig{
		Host:     "cnpg-rw.seam-system.svc",
		Port:     "5432",
		DBName:   "guardian",
		User:     "guardian",
		Password: "secret",
	}
	dsn := cfg.DSN()
	expected := "host=cnpg-rw.seam-system.svc port=5432 dbname=guardian user=guardian password=secret sslmode=disable"
	if dsn != expected {
		t.Errorf("DSN mismatch\ngot:  %s\nwant: %s", dsn, expected)
	}
}
