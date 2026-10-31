package postgres

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Test-only local attestation: updates occur only while the writer owns the
// actor's exclusive fence. It is neither a production provider nor authentication.
type fixtureIdentity struct {
	actor, request string
	enabled        atomic.Bool
	calls          atomic.Int32
}

func (i *fixtureIdentity) CurrentCreation(ctx context.Context, r CreationIdentityRequest) (CreationAttestation, error) {
	i.calls.Add(1)
	if ctx.Err() != nil {
		return CreationAttestation{}, ctx.Err()
	}
	if r.ActorID != i.actor || r.RequestID != i.request {
		return CreationAttestation{}, errors.New("fixture identity binding unavailable")
	}
	return CreationAttestation{Actor: authz.Actor{ID: i.actor, Authenticated: i.enabled.Load(), Human: true}, RequestID: i.request}, nil
}

// Only test plumbing prepends role switching; production Check has no role hook.
type creationFixtureBoundary struct {
	db   *pg.DB
	role string
	wrap func(pg.Executor) pg.Executor
}

func (b creationFixtureBoundary) WithTx(ctx context.Context, s pg.Scope, fn func(context.Context, pg.Executor) error) error {
	return b.db.WithTx(ctx, s, func(ctx context.Context, tx pg.Executor) error {
		if b.role != "" {
			if err := restricted(ctx, tx, b.role); err != nil {
				return err
			}
		}
		if b.wrap != nil {
			tx = b.wrap(tx)
		}
		return fn(ctx, tx)
	})
}

type creationFixture struct {
	db       *pg.DB
	admin    *pgx.Conn
	role     string
	r        CreationRequest
	identity *fixtureIdentity
	checker  *CreationChecker
}

func newCreationFixture(t *testing.T, name string) *creationFixture {
	t.Helper()
	db, admin, role := database(t)
	r := CreationRequest{"ca-actor-" + name, "ca-org-" + name, "ca-member-" + name, "ca-request-" + name}
	ctx, end := context.WithTimeout(context.Background(), 5*time.Second)
	defer end()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		_ = tx.Rollback(c)
	}()
	// One-time isolated fixture provisioning, before any business transaction.
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO softteros_access.actors VALUES($1)", []any{r.ActorID}},
		{"INSERT INTO softteros_access.organizations VALUES($1)", []any{r.OrganizationID}},
		{"INSERT INTO softteros_access.actor_authority_fences VALUES($1,1)", []any{r.ActorID}},
		{"INSERT INTO softteros_access.organization_authority_fences VALUES($1,1)", []any{r.OrganizationID}},
		{"INSERT INTO softteros_access.memberships VALUES($1,$2,$3,true,false,'2000-01-01+00','9999-01-01+00')", []any{r.OrganizationID, r.MembershipID, r.ActorID}},
		{"INSERT INTO softteros_access.membership_enquiry_capabilities VALUES($1,$2,'enquiries.create')", []any{r.OrganizationID, r.MembershipID}},
	} {
		if _, err = tx.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	i := &fixtureIdentity{actor: r.ActorID, request: r.RequestID}
	i.enabled.Store(true)
	c, err := NewCreationChecker(db, i)
	if err != nil {
		t.Fatal(err)
	}
	c.db = creationFixtureBoundary{db: db, role: role}
	return &creationFixture{db, admin, role, r, i, c}
}
func (f *creationFixture) writer(t *testing.T, conn *pgx.Conn, actor bool) pgx.Tx {
	t.Helper()
	ctx := context.Background()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, end := context.WithTimeout(context.Background(), 3*time.Second)
		defer end()
		_ = tx.Rollback(c)
	})
	role := strings.TrimSuffix(f.role, "_runtime") + "_writer"
	if !strings.HasSuffix(f.role, "_runtime") || !identifier(role) {
		t.Fatal("invalid fixture writer role")
	}
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "SELECT set_config('softteros.actor_id',$1,true),set_config('softteros.organization_id',$2,true)", f.r.ActorID, f.r.OrganizationID); err != nil {
		t.Fatal(err)
	}
	if actor {
		if _, err = tx.Exec(ctx, "SELECT actor_id FROM softteros_access.actor_authority_fences WHERE actor_id=$1 FOR UPDATE", f.r.ActorID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(ctx, "SELECT organization_id FROM softteros_access.organization_authority_fences WHERE organization_id=$1 FOR UPDATE", f.r.OrganizationID); err != nil {
		t.Fatal(err)
	}
	if actor {
		if _, err = tx.Exec(ctx, "UPDATE softteros_access.actor_authority_fences SET revision=revision+1 WHERE actor_id=$1", f.r.ActorID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(ctx, "UPDATE softteros_access.organization_authority_fences SET revision=revision+1 WHERE organization_id=$1", f.r.OrganizationID); err != nil {
		t.Fatal(err)
	}
	return tx
}
func execAuthority(t *testing.T, tx pgx.Tx, q string, args ...any) {
	t.Helper()
	c, end := context.WithTimeout(context.Background(), 3*time.Second)
	defer end()
	if _, err := tx.Exec(c, q, args...); err != nil {
		t.Fatal(err)
	}
}
func commitAuthority(t *testing.T, tx pgx.Tx) {
	t.Helper()
	c, end := context.WithTimeout(context.Background(), 3*time.Second)
	defer end()
	if err := tx.Commit(c); err != nil {
		t.Fatal(err)
	}
}
func revokeCapability(t *testing.T, f *creationFixture, tx pgx.Tx) {
	execAuthority(t, tx, "DELETE FROM softteros_access.membership_enquiry_capabilities WHERE organization_id=$1 AND membership_id=$2 AND capability='enquiries.create'", f.r.OrganizationID, f.r.MembershipID)
}

func TestIntegrationCreationAuthorityDenials(t *testing.T) {
	for _, name := range []string{"valid", "inactive", "revoked", "expired", "future", "missing-member", "wrong-member", "wrong-org", "missing-actor", "disabled-actor", "missing-capability", "deleted-capability", "wrong-capability", "admin-without-capability", "missing-fence"} {
		t.Run(name, func(t *testing.T) {
			f := newCreationFixture(t, name)
			r := f.r
			if name == "deleted-capability" {
				if err := f.checker.Check(context.Background(), r); err != nil {
					t.Fatal("positive capability control", err)
				}
			}
			switch name {
			case "inactive", "revoked", "expired", "future":
				tx := f.writer(t, f.admin, false)
				q := map[string]string{"inactive": "active=false", "revoked": "revoked=true", "expired": "valid_until=clock_timestamp()", "future": "valid_from=clock_timestamp()+interval '1 hour'"}[name]
				execAuthority(t, tx, "UPDATE softteros_access.memberships SET "+q+" WHERE organization_id=$1 AND membership_id=$2", r.OrganizationID, r.MembershipID)
				commitAuthority(t, tx)
			case "missing-capability", "deleted-capability", "wrong-capability", "admin-without-capability":
				tx := f.writer(t, f.admin, false)
				revokeCapability(t, f, tx)
				if name == "wrong-capability" {
					execAuthority(t, tx, "INSERT INTO softteros_access.membership_enquiry_capabilities VALUES($1,$2,'enquiries.review')", r.OrganizationID, r.MembershipID)
				}
				commitAuthority(t, tx)
				if name == "admin-without-capability" {
					f.checker.db = creationFixtureBoundary{db: f.db}
				} // Actual privileged fixture login still gains no Go-policy bypass.
			case "missing-member":
				r.MembershipID = "missing-member"
			case "wrong-member":
				r.MembershipID = "member-1"
			case "wrong-org":
				r.OrganizationID = "org-1"
			case "missing-actor":
				r.ActorID = "missing-actor"
			case "disabled-actor":
				tx := f.writer(t, f.admin, true)
				f.identity.enabled.Store(false)
				commitAuthority(t, tx)
			case "missing-fence":
				// Privileged one-time corruption/absence fixture, not a runtime writer operation.
				if _, err := f.admin.Exec(context.Background(), "DELETE FROM softteros_access.actor_authority_fences WHERE actor_id=$1", r.ActorID); err != nil {
					t.Fatal(err)
				}
			}
			err := f.checker.Check(context.Background(), r)
			if name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, authz.ErrUnauthorized) {
				t.Fatal("expected safe default denial", err)
			}
		})
	}
}

type creationObserved struct {
	pg.Executor
	beforeClock func(int)
	clocks      int
	pid         chan<- uint32
	lockError   *string
}

func (o *creationObserved) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	if q == creationClockSQL {
		o.clocks++
		if o.beforeClock != nil {
			o.beforeClock(o.clocks)
		}
	}
	if q == creationFenceSQL && o.pid != nil {
		var pid uint32
		if err := o.Executor.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
			return creationRow(func(...any) error { return err })
		}
		o.pid <- pid
	}
	row := o.Executor.QueryRow(ctx, q, args...)
	return creationRow(func(dest ...any) error {
		err := row.Scan(dest...)
		var server *pgconn.PgError
		if q == creationFenceSQL && o.lockError != nil && errors.As(err, &server) {
			*o.lockError = server.Code
		}
		return err
	})
}
func waitAuthorityLock(t *testing.T, admin *pgx.Conn, pid uint32) {
	t.Helper()
	ctx, end := context.WithTimeout(context.Background(), 3*time.Second)
	defer end()
	// The writer connection may have a restricted LOCAL ROLE and a transaction
	// statistics snapshot. Observe only the known PID through an independent
	// administrative fixture connection, with fresh autocommit observations.
	observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal("lock observer connection", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = observer.Close(cleanup)
	}()
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := observer.QueryRow(ctx, "SELECT coalesce(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1", pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("positive control: authority transaction did not block on a real lock")
}
func authorityPID(t *testing.T, ch <-chan uint32) uint32 {
	t.Helper()
	select {
	case pid := <-ch:
		return pid
	case <-time.After(3 * time.Second):
		t.Fatal("authority operation did not reach its fence query")
		return 0
	}
}

func authorityResult(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(4 * time.Second):
		t.Fatal("authority operation exceeded bounded completion")
		return nil
	}
}
func waitAuthorityExpiry(t *testing.T, f *creationFixture) {
	t.Helper()
	ctx, end := context.WithTimeout(context.Background(), 4*time.Second)
	defer end()
	for ctx.Err() == nil {
		var expired bool
		if err := f.admin.QueryRow(ctx, "SELECT clock_timestamp()>=valid_until FROM softteros_access.memberships WHERE organization_id=$1 AND membership_id=$2", f.r.OrganizationID, f.r.MembershipID).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("database expiry boundary not reached")
}

func TestIntegrationCreationRevocationFirst(t *testing.T) {
	for _, kind := range []string{"capability", "membership", "actor"} {
		t.Run(kind, func(t *testing.T) {
			f := newCreationFixture(t, "revocation-"+kind)
			if err := f.checker.Check(context.Background(), f.r); err != nil {
				t.Fatal("positive initial authority", err)
			}
			f.identity.calls.Store(0)
			tx := f.writer(t, f.admin, kind == "actor")
			pid := make(chan uint32, 1)
			done := make(chan error, 1)
			f.checker.db = creationFixtureBoundary{db: f.db, role: f.role, wrap: func(e pg.Executor) pg.Executor { return &creationObserved{Executor: e, pid: pid} }}
			go func() { done <- f.checker.Check(context.Background(), f.r) }()
			waitAuthorityLock(t, f.admin, authorityPID(t, pid))
			if f.identity.calls.Load() != 0 {
				t.Fatal("identity read before fence acquisition")
			}
			switch kind {
			case "capability":
				revokeCapability(t, f, tx)
			case "membership":
				execAuthority(t, tx, "UPDATE softteros_access.memberships SET revoked=true WHERE organization_id=$1 AND membership_id=$2", f.r.OrganizationID, f.r.MembershipID)
			case "actor":
				f.identity.enabled.Store(false)
			}
			commitAuthority(t, tx)
			if err := authorityResult(t, done); !errors.Is(err, authz.ErrUnauthorized) {
				t.Fatal("post-wait revocation was not observed", err)
			}
		})
	}
}

func TestIntegrationCreationBusinessFirst(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		name := "commit"
		if rollback {
			name = "rollback"
		}
		t.Run(name, func(t *testing.T) {
			f := newCreationFixture(t, "business-"+name)
			writer, err := pgx.ConnectConfig(context.Background(), f.admin.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, end := context.WithTimeout(context.Background(), 3*time.Second)
				defer end()
				_ = writer.Close(ctx)
			})
			paused, release := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			sentinel := errors.New("synthetic business rollback")
			done := make(chan error, 1)
			f.checker.db = creationFixtureBoundary{db: f.db, role: f.role, wrap: func(e pg.Executor) pg.Executor {
				return &creationObserved{Executor: e, beforeClock: func(n int) {
					if n == 2 {
						close(paused)
						<-release
					}
				}}
			}}
			go func() {
				if rollback {
					done <- f.db.WithTx(context.Background(), pg.Scope{ActorID: f.r.ActorID, OrganizationID: f.r.OrganizationID}, func(ctx context.Context, e pg.Executor) error {
						if err := restricted(ctx, e, f.role); err != nil {
							return err
						}
						o := &creationObserved{Executor: e, beforeClock: func(n int) {
							if n == 2 {
								close(paused)
								<-release
							}
						}}
						if err := f.checker.authorize(ctx, o, f.r); err != nil {
							return err
						}
						return sentinel
					})
				} else {
					done <- f.checker.Check(context.Background(), f.r)
				}
			}()
			select {
			case <-paused:
			case <-time.After(3 * time.Second):
				t.Fatal("business authority did not reach final check")
			}
			var writerPID uint32
			if err := writer.QueryRow(context.Background(), "SELECT pg_backend_pid()").Scan(&writerPID); err != nil {
				t.Fatal(err)
			}
			writerDone := make(chan error, 1)
			go func() {
				ctx, end := context.WithTimeout(context.Background(), 3*time.Second)
				defer end()
				tx, err := writer.Begin(ctx)
				if err != nil {
					writerDone <- err
					return
				}
				defer tx.Rollback(context.Background())
				role := strings.TrimSuffix(f.role, "_runtime") + "_writer"
				for _, q := range []struct {
					sql  string
					args []any
				}{
					{"SET LOCAL ROLE " + pgx.Identifier{role}.Sanitize(), nil},
					{"SELECT set_config('softteros.actor_id',$1,true),set_config('softteros.organization_id',$2,true)", []any{f.r.ActorID, f.r.OrganizationID}},
					{"SELECT actor_id FROM softteros_access.actor_authority_fences WHERE actor_id=$1 FOR UPDATE", []any{f.r.ActorID}},
					{"SELECT organization_id FROM softteros_access.organization_authority_fences WHERE organization_id=$1 FOR UPDATE", []any{f.r.OrganizationID}},
					{"UPDATE softteros_access.actor_authority_fences SET revision=revision+1 WHERE actor_id=$1", []any{f.r.ActorID}},
					{"UPDATE softteros_access.organization_authority_fences SET revision=revision+1 WHERE organization_id=$1", []any{f.r.OrganizationID}},
					{"DELETE FROM softteros_access.membership_enquiry_capabilities WHERE organization_id=$1 AND membership_id=$2", []any{f.r.OrganizationID, f.r.MembershipID}},
				} {
					if _, err = tx.Exec(ctx, q.sql, q.args...); err != nil {
						writerDone <- err
						return
					}
				}
				writerDone <- tx.Commit(ctx)
			}()
			waitAuthorityLock(t, f.admin, writerPID)
			select {
			case err := <-writerDone:
				t.Fatal("writer passed held fences", err)
			default:
			}
			close(release)
			err = authorityResult(t, done)
			if rollback {
				if !errors.Is(err, sentinel) {
					t.Fatal("rollback not preserved", err)
				}
			} else if err != nil {
				t.Fatal("command-first authorization failed", err)
			}
			if err := authorityResult(t, writerDone); err != nil {
				t.Fatal("writer did not proceed after transaction end", err)
			}
			f.checker.db = creationFixtureBoundary{db: f.db, role: f.role}
			if err := f.checker.Check(context.Background(), f.r); !errors.Is(err, authz.ErrUnauthorized) {
				t.Fatal("committed revocation not enforced", err)
			}
		})
	}
}

func TestIntegrationCreationExpiry(t *testing.T) {
	for _, duringWait := range []bool{true, false} {
		name := "final"
		if duringWait {
			name = "waiting"
		}
		t.Run(name, func(t *testing.T) {
			f := newCreationFixture(t, "expiry-"+name)
			tx := f.writer(t, f.admin, false)
			interval := "2 seconds"
			if duringWait {
				interval = "200 milliseconds"
			}
			execAuthority(t, tx, "UPDATE softteros_access.memberships SET valid_until=clock_timestamp()+$3::text::interval WHERE organization_id=$1 AND membership_id=$2", f.r.OrganizationID, f.r.MembershipID, interval)
			if !duringWait {
				commitAuthority(t, tx)
			}
			pid := make(chan uint32, 1)
			paused, release := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			f.checker.db = creationFixtureBoundary{db: f.db, role: f.role, wrap: func(e pg.Executor) pg.Executor {
				return &creationObserved{Executor: e, pid: pid, beforeClock: func(n int) {
					if n == 2 && !duringWait {
						close(paused)
						<-release
					}
				}}
			}}
			done := make(chan error, 1)
			go func() { done <- f.checker.Check(context.Background(), f.r) }()
			backend := authorityPID(t, pid)
			if duringWait {
				waitAuthorityLock(t, f.admin, backend)
			} else {
				select {
				case <-paused:
				case <-time.After(3 * time.Second):
					t.Fatal("initial authorization was not valid")
				}
			}
			waitAuthorityExpiry(t, f)
			if duringWait {
				commitAuthority(t, tx)
			} else {
				close(release)
			}
			if err := authorityResult(t, done); !errors.Is(err, authz.ErrUnauthorized) {
				t.Fatal("fresh expiry check missing", err)
			}
		})
	}
}

func TestIntegrationCreationCancellationAndLockDeadlines(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "lock"} {
		t.Run(mode, func(t *testing.T) {
			f := newCreationFixture(t, "bounded-"+mode)
			tx := f.writer(t, f.admin, false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "deadline" {
				ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
				defer cancel()
			}
			pid := make(chan uint32, 1)
			var lockError string
			f.checker.db = creationFixtureBoundary{db: f.db, role: f.role, wrap: func(e pg.Executor) pg.Executor {
				return &creationObserved{Executor: e, pid: pid, lockError: &lockError}
			}}
			done := make(chan error, 1)
			go func() { done <- f.checker.Check(ctx, f.r) }()
			waitAuthorityLock(t, f.admin, authorityPID(t, pid))
			if mode == "cancel" {
				cancel()
			}
			err := authorityResult(t, done)
			if !errors.Is(err, ErrCreationUnavailable) {
				t.Fatal("blocked authority did not fail safely", err)
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation marker missing", err)
			}
			if mode == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("deadline marker missing", err)
			}
			if mode == "lock" && lockError != "55P03" {
				t.Fatal("wrong SQL lock deadline outcome", lockError)
			}
			if f.identity.calls.Load() != 0 {
				t.Fatal("attestation read despite blocked fence")
			}
			if err := tx.Rollback(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.checker.db = creationFixtureBoundary{db: f.db, role: f.role}
			if err := f.checker.Check(context.Background(), f.r); err != nil {
				t.Fatal("pool/fence cleanup failed", err)
			}
		})
	}
}
