package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Only scripts/test-postgres-go.py supplies these synthetic disposable targets.
// Administrative connection and SET SESSION AUTHORIZATION are test plumbing.
// Production Config/Open have no role-switching hook or migration credentials.
func integrationDB(t *testing.T) *DB {
	t.Helper()
	if os.Getenv("SOFTTEROS_PG_INTEGRATION") != "1" {
		t.Skip("run scripts/test-postgres-go.py for real PostgreSQL tests")
	}
	c := DefaultConfig(os.Getenv("SOFTTEROS_TEST_SOCKET"), 5432, os.Getenv("SOFTTEROS_TEST_DATABASE"), os.Getenv("USER"))
	c.MaxConns = 1
	c.AcquireTimeout = 200 * time.Millisecond
	pc, err := poolConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	role := os.Getenv("SOFTTEROS_TEST_RUNTIME")
	if !validID(role) {
		t.Fatal("missing synthetic runtime role")
	}
	pc.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET SESSION AUTHORIZATION "+pgx.Identifier{role}.Sanitize())
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), pc)
	if err != nil {
		t.Fatal("test pool configuration failed")
	}
	d := wrap(pool, c)
	t.Cleanup(func() {
		if err := d.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if err = d.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	return d
}

var scopeA = Scope{OrganizationID: "org-1", ActorID: "actor-1"}
var scopeB = Scope{OrganizationID: "org-2", ActorID: "actor-1"}
var scopeC = Scope{OrganizationID: "org-1", ActorID: "actor-2"}
var scopeD = Scope{OrganizationID: "org-2", ActorID: "actor-2"}

func queryInt(t *testing.T, d *DB, s Scope, q string, args ...any) int {
	t.Helper()
	var n int
	if err := d.WithTx(context.Background(), s, func(ctx context.Context, e Executor) error { return e.QueryRow(ctx, q, args...).Scan(&n) }); err != nil {
		t.Fatal(err)
	}
	return n
}

func idle(t *testing.T, d *DB) uint32 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := d.pool.Acquire(ctx)
	if err != nil {
		t.Fatal("no reusable connection")
	}
	defer c.Release()
	if !clean(ctx, c.Conn()) {
		t.Fatal("dirty connection returned to pool")
	}
	var count int
	if err = c.QueryRow(ctx, "SELECT count(*) FROM softteros_access.organizations").Scan(&count); err != nil || count != 0 {
		t.Fatal("no-context RLS access leaked")
	}
	return c.Conn().PgConn().PID()
}

func TestIntegrationReadinessAndScope(t *testing.T) {
	d := integrationDB(t)
	if err := d.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	err := d.WithTx(context.Background(), scopeA, func(ctx context.Context, e Executor) error {
		var roleOK bool
		var isolation string
		err := e.QueryRow(ctx, "SELECT current_user=session_user AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole FROM pg_roles WHERE rolname=current_user").Scan(&roleOK)
		if err != nil || !roleOK {
			t.Fatal("permission assertions did not use restricted session/effective identity")
		}
		if err = e.QueryRow(ctx, "SHOW transaction_isolation").Scan(&isolation); err != nil || isolation != "read committed" {
			t.Fatal("isolation mismatch")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []Scope{{}, {"org-1", "bad actor"}, {"org/2", "actor-1"}} {
		called := false
		if err := d.WithTx(context.Background(), scope, func(context.Context, Executor) error { called = true; return nil }); err != ErrScope || called {
			t.Fatal("invalid scope reached SQL callback")
		}
	}
	bad := DefaultConfig("/nonexistent-softteros-socket", 5432, "synthetic", "synthetic")
	if db, err := Open(context.Background(), bad); db != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("invalid endpoint readiness result")
	}
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.Ready(context.Background()) == nil {
		t.Fatal("closed pool ready")
	}
}

func TestIntegrationSequentialTenantReuse(t *testing.T) {
	d := integrationDB(t)
	pid := idle(t, d)
	for _, rollback := range []bool{false, true} {
		for _, s := range []Scope{scopeA, scopeB, scopeC, scopeD} {
			sentinel := errors.New("synthetic rollback")
			err := d.WithTx(context.Background(), s, func(ctx context.Context, e Executor) error {
				var actorContext, orgContext, memberActor string
				if err := e.QueryRow(ctx, "SELECT current_setting('softteros.actor_id'), current_setting('softteros.organization_id')").Scan(&actorContext, &orgContext); err != nil {
					return err
				}
				if actorContext != s.ActorID || orgContext != s.OrganizationID {
					t.Fatal("actor/organization context did not preserve supplied scope")
				}
				if err := e.QueryRow(ctx, "SELECT actor_id FROM softteros_access.memberships WHERE actor_id=$1", s.ActorID).Scan(&memberActor); err != nil {
					return err
				}
				if memberActor != s.ActorID {
					t.Fatal("membership query returned another actor")
				}
				var org string
				if err := e.QueryRow(ctx, "SELECT organization_id FROM softteros_access.organizations").Scan(&org); err != nil {
					return err
				}
				if org != s.OrganizationID {
					t.Fatal("omitted filter crossed tenant boundary")
				}
				if rollback {
					return sentinel
				}
				return nil
			})
			if rollback && !errors.Is(err, sentinel) || !rollback && err != nil {
				t.Fatal("transaction completion result", err)
			}
			if idle(t, d) != pid {
				t.Fatal("clean one-connection pool did not reuse backend")
			}
		}
	}
}

func TestIntegrationCommitRollbackCancelPanic(t *testing.T) {
	d := integrationDB(t)
	insert := func(ctx context.Context, e Executor, id int) error {
		_, err := e.Exec(ctx, "INSERT INTO step2_fixture.probe VALUES ($1,$2)", scopeA.OrganizationID, id)
		return err
	}
	if err := d.WithTx(context.Background(), scopeA, func(c context.Context, e Executor) error { return insert(c, e, 1) }); err != nil {
		t.Fatal(err)
	}
	count := func(id int) int {
		return queryInt(t, d, scopeA, "SELECT count(*) FROM step2_fixture.probe WHERE value=$1", id)
	}
	if count(1) != 1 {
		t.Fatal("commit not durable")
	}
	if err := d.WithTx(context.Background(), scopeA, func(c context.Context, e Executor) error { return insert(c, e, 1) }); err != ErrCommitRejected || count(1) != 1 {
		t.Fatal("deferred commit rejection misclassified", err)
	}
	sentinel := errors.New("synthetic callback failure")
	err := d.WithTx(context.Background(), scopeA, func(c context.Context, e Executor) error {
		if err := insert(c, e, 2); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) || count(2) != 0 {
		t.Fatal("callback failure did not roll back")
	}
	healthyPID := idle(t, d)
	ctx, cancel := context.WithCancel(context.Background())
	err = d.WithTx(ctx, scopeA, func(c context.Context, e Executor) error {
		if err := insert(c, e, 3); err != nil {
			return err
		}
		cancel()
		return nil
	})
	cancel()
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrCleanup) {
		t.Fatal("canceled request not rolled back independently")
	}
	if idle(t, d) != healthyPID {
		t.Fatal("healthy canceled transaction discarded instead of clean rollback")
	}
	// Observe rollback through a separately acquired pool/connection, rather
	// than relying on the canceled transaction's own view.
	observer := integrationDB(t)
	if queryInt(t, observer, scopeA, "SELECT count(*) FROM step2_fixture.probe WHERE value=3") != 0 {
		t.Fatal("independent observer saw canceled write")
	}
	panicValue := new(int)
	func() {
		defer func() {
			if recover() != panicValue {
				t.Fatal("panic not propagated")
			}
		}()
		_ = d.WithTx(context.Background(), scopeA, func(c context.Context, e Executor) error {
			if err := insert(c, e, 4); err != nil {
				t.Fatal(err)
			}
			panic(panicValue)
		})
	}()
	if count(4) != 0 {
		t.Fatal("panic left partial write")
	}
	idle(t, d)
	// A request blocked in real server work is canceled, not just a pre-canceled callback.
	ctx, cancel = context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	err = d.WithTx(ctx, scopeA, func(c context.Context, e Executor) error { _, err := e.Exec(c, "SELECT pg_sleep(5)"); return err })
	if err == nil {
		t.Fatal("blocked query ignored deadline")
	}
	idle(t, d)
}

func TestIntegrationPoolExhaustion(t *testing.T) {
	d := integrationDB(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- d.WithTx(context.Background(), scopeA, func(ctx context.Context, e Executor) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("holder did not enter")
	}
	called := false
	start := time.Now()
	err := d.WithTx(context.Background(), scopeB, func(context.Context, Executor) error { called = true; return nil })
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) || called || time.Since(start) > time.Second {
		t.Fatal("acquisition was not bounded", err)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("holder did not finish")
	}
	idle(t, d)
}

func TestIntegrationDiscard(t *testing.T) {
	d := integrationDB(t)
	pid := idle(t, d)
	if err := d.WithTx(context.Background(), scopeA, func(ctx context.Context, e Executor) error {
		_, err := e.Exec(ctx, "SELECT set_config('softteros.actor_id','actor-1',false)")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if idle(t, d) == pid {
		t.Fatal("session contamination after commit was returned to pool")
	}
	pid = idle(t, d)
	// Simulate a faulty trusted adapter setting session-level tenant context.
	c, err := d.pool.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Exec(context.Background(), "SELECT set_config('softteros.organization_id','org-2',false)"); err != nil {
		t.Fatal(err)
	}
	c.Release()
	called := false
	err = d.WithTx(context.Background(), scopeA, func(context.Context, Executor) error { called = true; return nil })
	if err != ErrUnavailable || called {
		t.Fatal("residual scope accepted")
	}
	if idle(t, d) == pid {
		t.Fatal("contaminated connection reused")
	}
	pid = idle(t, d)
	// Test-only administrator terminates exactly this acquired fixture backend.
	// SET SESSION AUTHORIZATION is not a genuine login: backend ownership can
	// still reflect the peer bootstrap identity, so runtime self-signalling is
	// not a valid discard-test precondition.
	adminConfig, err := poolConfig(DefaultConfig(os.Getenv("SOFTTEROS_TEST_SOCKET"), 5432, os.Getenv("SOFTTEROS_TEST_DATABASE"), os.Getenv("USER")))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, adminConfig.ConnConfig)
	if err != nil {
		t.Fatal("fixture control connection failed")
	}
	defer func() { _ = admin.Close(context.Background()) }()
	err = d.WithTx(context.Background(), scopeA, func(ctx context.Context, e Executor) error {
		var acquired uint32
		if err := e.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&acquired); err != nil {
			return err
		}
		if acquired != pid {
			t.Fatal("unexpected test backend")
		}
		var terminated bool
		if err := admin.QueryRow(ctx, "SELECT pg_terminate_backend($1)", acquired).Scan(&terminated); err != nil || !terminated {
			t.Fatal("fixture backend termination failed")
		}
		_, err := e.Exec(ctx, "SELECT 1")
		return err
	})
	if err == nil {
		t.Fatal("dead connection succeeded")
	}
	if idle(t, d) == pid {
		t.Fatal("dead backend reused")
	}
	pid = idle(t, d)
	calls := 0
	err = d.WithTx(context.Background(), scopeA, func(ctx context.Context, e Executor) error {
		calls++
		var acquired uint32
		if err := e.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&acquired); err != nil {
			return err
		}
		if acquired != pid {
			t.Fatal("unexpected commit-loss fixture backend")
		}
		var killed bool
		if err := admin.QueryRow(ctx, "SELECT pg_terminate_backend($1)", acquired).Scan(&killed); err != nil || !killed {
			t.Fatal("commit-loss fixture termination failed")
		}
		return nil // Commit is the next operation; no rollback acknowledgement is available.
	})
	if err != ErrCommitUnknown || calls != 1 {
		t.Fatal("lost connection during commit was retried or reported as rollback", err)
	}
	if idle(t, d) == pid {
		t.Fatal("uncertain-commit connection reused")
	}
	idle(t, d) // Includes protocol idle status, empty scope and zero unfiltered rows.
}

func TestIntegrationCloseCancelsOperation(t *testing.T) {
	d := integrationDB(t)
	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- d.WithTx(context.Background(), scopeA, func(ctx context.Context, e Executor) error { close(entered); <-ctx.Done(); return ctx.Err() })
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("operation did not enter")
	}
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("shutdown did not cancel operation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("operation leaked")
	}
}
