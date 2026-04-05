// Package database provides the CNPG database client and migration runner for
// Guardian's persistent storage layer.
//
// Guardian on the management cluster (role=management) uses CNPG for persistent
// EPG state, audit event storage, and identity resolution logs. guardian-schema.md §16.
//
// The MigrationRunner connects to CNPG before any controller registration and
// applies pending migrations in declared order. If CNPG is unreachable, the
// runner emits a CNPGUnreachable condition and retries — it does not crash.
// guardian-schema.md §3 Step 1.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// NOTE: A PostgreSQL driver (e.g. github.com/jackc/pgx/v5/stdlib) must be
// blank-imported by the binary that calls Open(). The database package itself
// does not import a driver so that tests using mock DB implementations are not
// forced to link against the driver. The driver import belongs in
// cmd/ont-security/main.go, added when CNPG phase 0 is wired (F-P8).

// AuditDatabase is the interface through which Guardian accesses the CNPG-backed
// audit_events table. It is defined here (database package) so that the controller
// can import it without creating an import cycle between controller and database.
// Test code uses mock implementations of this interface.
type AuditDatabase interface {
	// EventExists reports whether an event with the given clusterID and sequenceNumber
	// already exists in the audit_events table.
	EventExists(ctx context.Context, clusterID string, sequenceNumber int64) (bool, error)

	// InsertEvent inserts a single audit event into the audit_events table.
	InsertEvent(ctx context.Context, event AuditEvent) error
}

// AuditEvent is a single audit event record written to the audit_events table.
type AuditEvent struct {
	ClusterID      string
	SequenceNumber int64
	Subject        string
	Action         string
	Resource       string
	Decision       string
	MatchedPolicy  string
}

// SQLAuditStore implements AuditDatabase using a sql.DB (CNPG backend).
type SQLAuditStore struct {
	db DB
}

// NewSQLAuditStore wraps db as an AuditDatabase implementation.
func NewSQLAuditStore(db DB) *SQLAuditStore {
	return &SQLAuditStore{db: db}
}

// EventExists queries the audit_events table for a matching (cluster_id, sequence_number) pair.
func (s *SQLAuditStore) EventExists(ctx context.Context, clusterID string, sequenceNumber int64) (bool, error) {
	var count int
	row := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_events WHERE cluster_id = $1 AND sequence_number = $2`,
		clusterID, sequenceNumber)
	if err := row.Scan(&count); err != nil {
		return false, fmt.Errorf("EventExists query: %w", err)
	}
	return count > 0, nil
}

// InsertEvent inserts a single event into the audit_events table.
func (s *SQLAuditStore) InsertEvent(ctx context.Context, event AuditEvent) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_events
			(cluster_id, subject, action, resource, decision, matched_policy, sequence_number)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		event.ClusterID, event.Subject, event.Action, event.Resource,
		event.Decision, event.MatchedPolicy, event.SequenceNumber,
	)
	if err != nil {
		return fmt.Errorf("InsertEvent: %w", err)
	}
	return nil
}

// SecretFields are the field names that CNPG provisioned Secrets contain.
// The Secret is read by internal/database/secret.go via the Kubernetes client.
const (
	SecretFieldHost     = "host"
	SecretFieldPort     = "port"
	SecretFieldDBName   = "dbname"
	SecretFieldUser     = "user"
	SecretFieldPassword = "password"
)

// ConnConfig holds the CNPG connection parameters resolved from the Secret.
type ConnConfig struct {
	Host     string
	Port     string
	DBName   string
	User     string
	Password string
}

// DSN returns a PostgreSQL connection string for this configuration.
func (c ConnConfig) DSN() string {
	return fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		c.Host, c.Port, c.DBName, c.User, c.Password)
}

// DB is the interface that wraps the minimal database operations used by Guardian.
// It is satisfied by *sql.DB and by test mocks.
type DB interface {
	// QueryRowContext executes a query returning at most one row.
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row

	// ExecContext executes a query without returning rows.
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)

	// PingContext verifies the connection to the database is still alive.
	PingContext(ctx context.Context) error
}

// Open opens a connection to the CNPG PostgreSQL database described by cfg.
// The returned *sql.DB is valid and pinged before return.
func Open(cfg ConnConfig) (*sql.DB, error) {
	db, err := sql.Open("postgres", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("sql.Open: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping CNPG: %w", err)
	}
	return db, nil
}

// migration is a single SQL migration to be applied in order.
type migration struct {
	id  int
	sql string
}

// migrations is the ordered list of schema migrations Guardian applies.
// Migrations are applied exactly once — the MigrationRunner tracks applied
// migrations in the schema_migrations table.
//
// Migration 001: audit_events — persistent audit log for all authorization decisions.
// Migration 002: permission_cache — short-lived cache for EPG decision results.
// Migration 003: identity_resolution_log — record of identity provider resolutions.
var migrations = []migration{
	{
		id: 1,
		sql: `CREATE TABLE IF NOT EXISTS audit_events (
			id              BIGSERIAL    PRIMARY KEY,
			cluster_id      TEXT         NOT NULL,
			subject         TEXT         NOT NULL,
			action          TEXT         NOT NULL,
			resource        TEXT         NOT NULL,
			decision        TEXT         NOT NULL,
			matched_policy  TEXT         NOT NULL,
			sequence_number BIGINT       NOT NULL,
			timestamp       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
		)`,
	},
	{
		id: 2,
		sql: `CREATE TABLE IF NOT EXISTS permission_cache (
			subject          TEXT         NOT NULL,
			action           TEXT         NOT NULL,
			resource         TEXT         NOT NULL,
			result           TEXT         NOT NULL,
			expires_at       TIMESTAMPTZ  NOT NULL,
			PRIMARY KEY (subject, action, resource)
		)`,
	},
	{
		id: 3,
		sql: `CREATE TABLE IF NOT EXISTS identity_resolution_log (
			id               BIGSERIAL    PRIMARY KEY,
			subject          TEXT         NOT NULL,
			provider_name    TEXT         NOT NULL,
			resolved_profile TEXT         NOT NULL,
			resolved_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
		)`,
	},
}

// MigrationRunner applies pending database migrations to a CNPG instance.
// It is the only component that writes to the schema_migrations table.
// guardian-schema.md §3 Step 1.
type MigrationRunner struct {
	db DB
}

// NewMigrationRunner constructs a MigrationRunner backed by the given DB.
func NewMigrationRunner(db DB) *MigrationRunner {
	return &MigrationRunner{db: db}
}

// Run applies all pending migrations in declared order. It first ensures the
// schema_migrations table exists, then applies each migration that has not yet
// been recorded. Run is idempotent — it is safe to call on a cluster rebuild.
func (r *MigrationRunner) Run(ctx context.Context) error {
	if err := r.ensureMigrationsTable(ctx); err != nil {
		return fmt.Errorf("ensure schema_migrations table: %w", err)
	}
	for _, m := range migrations {
		applied, err := r.isApplied(ctx, m.id)
		if err != nil {
			return fmt.Errorf("check migration %d: %w", m.id, err)
		}
		if applied {
			continue
		}
		if err := r.apply(ctx, m); err != nil {
			return fmt.Errorf("apply migration %d: %w", m.id, err)
		}
	}
	return nil
}

// ensureMigrationsTable creates schema_migrations if it does not exist.
func (r *MigrationRunner) ensureMigrationsTable(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		id          INT          PRIMARY KEY,
		applied_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
	)`)
	return err
}

// isApplied returns true if migration id has already been recorded.
func (r *MigrationRunner) isApplied(ctx context.Context, id int) (bool, error) {
	var count int
	row := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE id = $1`, id)
	if err := row.Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// apply executes the migration SQL and records it in schema_migrations.
func (r *MigrationRunner) apply(ctx context.Context, m migration) error {
	if _, err := r.db.ExecContext(ctx, m.sql); err != nil {
		return fmt.Errorf("execute DDL: %w", err)
	}
	if _, err := r.db.ExecContext(ctx,
		`INSERT INTO schema_migrations (id) VALUES ($1)`, m.id); err != nil {
		return fmt.Errorf("record migration: %w", err)
	}
	return nil
}
