// Package postgres is trusted infrastructure, not authentication or authorization.
// Driver types stay here; domain and authorization packages remain driver-free.
package postgres

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrConfig         = errors.New("invalid PostgreSQL configuration")
	ErrScope          = errors.New("invalid PostgreSQL scope")
	ErrUnavailable    = errors.New("PostgreSQL unavailable")
	ErrTransaction    = errors.New("PostgreSQL transaction failed")
	ErrCleanup        = errors.New("PostgreSQL cleanup failed")
	ErrCommitRejected = errors.New("PostgreSQL commit rejected; transaction rolled back")
	ErrCommitUnknown  = errors.New("PostgreSQL commit outcome unknown; do not retry automatically")
)

// Config is explicit trusted configuration. Never log it: Password is sensitive.
// TCP requires verified TLS; a filesystem socket uses the server's local auth.
type Config struct {
	Host, Database, User, Password                                   string
	Port                                                             uint16
	TLS                                                              *tls.Config
	MaxConns                                                         int32
	ConnectTimeout, AcquireTimeout, OperationTimeout, CleanupTimeout time.Duration
	StatementTimeout, LockTimeout, IdleTransactionTimeout            time.Duration
	MaxConnLifetime, MaxConnIdleTime                                 time.Duration
}

// DefaultConfig supplies finite infrastructure budgets, not business policy.
func DefaultConfig(host string, port uint16, database, user string) Config {
	return Config{Host: host, Port: port, Database: database, User: user, MaxConns: 4,
		ConnectTimeout: 5 * time.Second, AcquireTimeout: 2 * time.Second,
		OperationTimeout: 20 * time.Second, CleanupTimeout: 3 * time.Second,
		StatementTimeout: 10 * time.Second, LockTimeout: 500 * time.Millisecond,
		IdleTransactionTimeout: 10 * time.Second, MaxConnLifetime: 30 * time.Minute,
		MaxConnIdleTime: 5 * time.Minute}
}

func poolConfig(c Config) (*pgxpool.Config, error) {
	// The upstream parser eagerly resolves PGSERVICE. Refuse it before parsing
	// rather than reading an ambient file or mutating process-wide environment.
	if os.Getenv("PGSERVICE") != "" {
		return nil, ErrConfig
	}
	for _, value := range []string{c.Host, c.Database, c.User} {
		if value == "" || strings.ContainsAny(value, "\x00\r\n,") {
			return nil, ErrConfig
		}
	}
	if c.Port == 0 || c.MaxConns < 1 || c.MaxConns > 64 || strings.ContainsRune(c.Password, 0) {
		return nil, ErrConfig
	}
	for _, d := range []time.Duration{c.ConnectTimeout, c.AcquireTimeout, c.OperationTimeout, c.CleanupTimeout,
		c.StatementTimeout, c.LockTimeout, c.IdleTransactionTimeout, c.MaxConnLifetime, c.MaxConnIdleTime} {
		if d < time.Millisecond || d > 24*time.Hour {
			return nil, ErrConfig
		}
	}
	if c.LockTimeout >= c.StatementTimeout || c.StatementTimeout > c.OperationTimeout ||
		c.IdleTransactionTimeout > c.OperationTimeout {
		return nil, ErrConfig
	}
	if !filepath.IsAbs(c.Host) && (c.TLS == nil || c.TLS.InsecureSkipVerify || c.TLS.ServerName == "") {
		return nil, ErrConfig
	}
	// A null passfile and refusal of PGSERVICE prevent ambient credential-file
	// discovery. Replace all runtime parameters, fallbacks and endpoint facts.
	pc, err := pgxpool.ParseConfig("host=localhost port=5432 dbname=postgres user=postgres password='' connect_timeout=5 passfile='" + os.DevNull + "' sslmode=disable")
	if err != nil {
		return nil, ErrConfig
	}
	cc := pc.ConnConfig
	cc.Host, cc.Port, cc.Database, cc.User, cc.Password = c.Host, c.Port, c.Database, c.User, c.Password
	cc.Fallbacks = nil
	cc.TLSConfig = nil
	if c.TLS != nil {
		cc.TLSConfig = c.TLS.Clone()
	}
	cc.ConnectTimeout = c.ConnectTimeout
	cc.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
	cc.RuntimeParams = map[string]string{
		"application_name": "softteros-infrastructure", "timezone": "UTC",
		"search_path": "pg_catalog", "softteros.organization_id": "", "softteros.actor_id": "",
		"statement_timeout": millis(c.StatementTimeout), "lock_timeout": millis(c.LockTimeout),
		"idle_in_transaction_session_timeout": millis(c.IdleTransactionTimeout),
		"transaction_timeout":                 millis(c.OperationTimeout),
	}
	pc.MaxConns, pc.MinConns = c.MaxConns, 0
	pc.MinIdleConns = 0
	pc.MaxConnLifetime, pc.MaxConnIdleTime = c.MaxConnLifetime, c.MaxConnIdleTime
	pc.HealthCheckPeriod = 30 * time.Second
	return pc, nil
}

func millis(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }

// Scope must come from a trusted caller; syntactic validity proves no authority.
type Scope struct{ OrganizationID, ActorID string }

func validID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i, b := range []byte(s) {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			continue
		}
		if i > 0 && (b == '_' || b == '-') {
			continue
		}
		return false
	}
	return true
}

// Executor deliberately offers no connection, savepoint, commit or rollback API.
// Callbacks are trusted, sequential, honor ctx, close rows, and must not retain
// this handle or issue transaction/session-control SQL. No client SQL belongs here.
type Executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}
type executor struct{ tx pgx.Tx }

func (e executor) Exec(c context.Context, q string, a ...any) (pgconn.CommandTag, error) {
	return e.tx.Exec(c, q, a...)
}
func (e executor) Query(c context.Context, q string, a ...any) (pgx.Rows, error) {
	return e.tx.Query(c, q, a...)
}
func (e executor) QueryRow(c context.Context, q string, a ...any) pgx.Row {
	return e.tx.QueryRow(c, q, a...)
}

type DB struct {
	pool    *pgxpool.Pool
	config  Config
	life    context.Context
	cancel  context.CancelFunc
	closing sync.Once
	done    chan struct{}
}

func wrap(pool *pgxpool.Pool, c Config) *DB {
	life, cancel := context.WithCancel(context.Background())
	return &DB{pool: pool, config: c, life: life, cancel: cancel, done: make(chan struct{})}
}

// Open establishes readiness before returning. Errors do not include driver
// messages, configuration values, credentials, or connection strings.
func Open(ctx context.Context, c Config) (*DB, error) {
	pc, err := poolConfig(c)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, ErrUnavailable
	}
	d := wrap(pool, c)
	if err = d.Ready(ctx); err != nil {
		_ = d.Close(context.Background())
		return nil, err
	}
	return d, nil
}

func (d *DB) operation(ctx context.Context) (context.Context, func()) {
	op, cancel := context.WithTimeout(ctx, d.config.OperationTimeout)
	stop := context.AfterFunc(d.life, cancel)
	return op, func() { stop(); cancel() }
}

func (d *DB) acquire(ctx context.Context) (*pgxpool.Conn, error) {
	a, cancel := context.WithTimeout(ctx, d.config.AcquireTimeout)
	defer cancel()
	conn, err := d.pool.Acquire(a)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, a.Err())
	}
	if !clean(a, conn.Conn()) {
		d.discard(conn)
		return nil, ErrUnavailable
	}
	return conn, nil
}

func clean(ctx context.Context, c *pgx.Conn) bool {
	if c.IsClosed() || c.PgConn().IsBusy() || c.PgConn().TxStatus() != 'I' {
		return false
	}
	var org, actor *string
	err := c.QueryRow(ctx, "SELECT nullif(current_setting('softteros.organization_id',true),''), nullif(current_setting('softteros.actor_id',true),'')").Scan(&org, &actor)
	return err == nil && org == nil && actor == nil
}

func (d *DB) discard(c *pgxpool.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), d.config.CleanupTimeout)
	defer cancel()
	// Hijack removes the resource from the pool even if graceful close fails.
	_ = c.Hijack().Close(ctx)
}
func (d *DB) release(c *pgxpool.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), d.config.CleanupTimeout)
	defer cancel()
	if !clean(ctx, c.Conn()) {
		d.discard(c)
		return
	}
	c.Release()
}

func (d *DB) Ready(ctx context.Context) error {
	op, cancel := d.operation(ctx)
	defer cancel()
	ready, end := context.WithTimeout(op, d.config.ConnectTimeout)
	defer end()
	c, err := d.acquire(ready)
	if err != nil {
		return err
	}
	defer d.release(c)
	if c.Ping(ready) != nil {
		return ErrUnavailable
	}
	return nil
}

// Close cancels in-flight operations and bounds the caller's wait. Callbacks
// that ignore cancellation cannot be forcibly interrupted by Go; closure then
// continues until they return, and ErrCleanup reports the incomplete wait.
func (d *DB) Close(ctx context.Context) error {
	d.closing.Do(func() { d.cancel(); go func() { d.pool.Close(); close(d.done) }() })
	bounded, cancel := context.WithTimeout(ctx, d.config.CleanupTimeout)
	defer cancel()
	select {
	case <-d.done:
		return nil
	case <-bounded.Done():
		return ErrCleanup
	}
}

// WithTx returns success only after a confirmed commit. Callback errors are
// returned to the trusted caller, who must sanitize them at any future transport
// boundary. All driver-originated boundary errors are stable, safe categories.
// Callback results are candidates until WithTx returns nil; callbacks must not
// publish success or perform external side effects inside the transaction.
func (d *DB) WithTx(ctx context.Context, scope Scope, fn func(context.Context, Executor) error) (err error) {
	if !validID(scope.OrganizationID) || !validID(scope.ActorID) || fn == nil {
		return ErrScope
	}
	op, cancel := d.operation(ctx)
	defer cancel()
	c, err := d.acquire(op)
	if err != nil {
		return err
	}
	tx, err := c.BeginTx(op, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		d.discard(c)
		return ErrTransaction
	}
	finished := false
	defer func() {
		if c == nil {
			return
		}
		if !finished {
			cleanup, end := context.WithTimeout(context.Background(), d.config.CleanupTimeout)
			rb := tx.Rollback(cleanup)
			end()
			if rb != nil {
				d.discard(c)
				err = errors.Join(err, ErrCleanup)
				return
			}
		}
		d.release(c)
	}()
	var org, actor string
	err = tx.QueryRow(op, "SELECT set_config('softteros.organization_id',$1,true), set_config('softteros.actor_id',$2,true)", scope.OrganizationID, scope.ActorID).Scan(&org, &actor)
	if err != nil || org != scope.OrganizationID || actor != scope.ActorID {
		return ErrTransaction
	}
	if op.Err() != nil {
		return op.Err()
	}
	if err = fn(op, executor{tx}); err != nil {
		return err
	}
	if op.Err() != nil {
		return op.Err()
	}
	if c.Conn().PgConn().TxStatus() == 'I' {
		finished = true
		d.discard(c)
		c = nil
		return ErrCommitUnknown
	}
	err = tx.Commit(op)
	finished = true
	if err != nil {
		d.discard(c)
		c = nil
		return commitError(err)
	}
	return nil
}

func commitError(err error) error {
	if errors.Is(err, pgx.ErrTxCommitRollback) {
		return ErrCommitRejected
	}
	var server *pgconn.PgError
	if errors.As(err, &server) && server.Severity == "ERROR" &&
		(strings.HasPrefix(server.Code, "23") || server.Code == "40001" || server.Code == "40P01" || server.Code == "25P02") {
		return ErrCommitRejected
	}
	return ErrCommitUnknown
}
