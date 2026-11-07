package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type persistentFixture struct {
	*creationFixture
	creator *FirstCreator
	key     [32]byte
	ids     atomic.Int32
}

func persistent(t *testing.T, name string) *persistentFixture {
	t.Helper()
	f := &persistentFixture{creationFixture: newCreationFixture(t, "persist-"+name)}
	// This fixture's random key stays stable across all its attempts/creators.
	if _, err := rand.Read(f.key[:]); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	c, err := NewFirstCreator(f.db, f.identity, f.key[:], func() (string, error) { return "persist-" + name + "-" + strconv.Itoa(int(f.ids.Add(1))), nil })
	if err != nil {
		t.Fatal(err)
	}
	c.authority.db = creationFixtureBoundary{db: f.db, role: f.role}
	f.creator = c
	return f
}
func peerCreator(t *testing.T, f *persistentFixture) *FirstCreator {
	t.Helper()
	db, _, role := database(t)
	c, err := NewFirstCreator(db, f.identity, f.key[:], f.creator.newID)
	if err != nil {
		t.Fatal(err)
	}
	c.authority.db = creationFixtureBoundary{db: db, role: role}
	return c
}

type creationCompletion struct {
	result Created
	err    error
}

func startCreation(c *FirstCreator, r CreationRequest, key string, input enquiries.Input, ctx context.Context) <-chan creationCompletion {
	done := make(chan creationCompletion, 1)
	go func() { result, err := c.Create(ctx, r, key, input); done <- creationCompletion{result, err} }()
	return done
}
func completedCreation(t *testing.T, done <-chan creationCompletion) creationCompletion {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("creation did not finish within deadline")
		return creationCompletion{}
	}
}
func noCreated(t *testing.T, c creationCompletion, want error) {
	t.Helper()
	if !errors.Is(c.err, want) || !reflect.DeepEqual(c.result, Created{}) {
		t.Fatal("unexpected failed creation result", c.err)
	}
}
func creationCounts(t *testing.T, f *persistentFixture, want [3]int) {
	t.Helper()
	ctx, end := context.WithTimeout(context.Background(), 3*time.Second)
	defer end()
	var counts [3]int
	err := f.admin.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM softteros_enquiries.enquiries WHERE organization_id=$1),
 (SELECT count(*) FROM softteros_enquiries.enquiry_events WHERE organization_id=$1),
 (SELECT count(*) FROM softteros_enquiries.enquiry_command_receipts WHERE organization_id=$1)`, f.r.OrganizationID).Scan(&counts[0], &counts[1], &counts[2])
	if err != nil || counts != want {
		t.Fatalf("independent committed counts: %v want %v; %v", counts, want, err)
	}
}

// Injection exists only in test plumbing, around the real transaction Executor.
type persistentObserved struct {
	pg.Executor
	before, after func(context.Context, string, []any) error
}

func (p *persistentObserved) Exec(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
	if p.before != nil {
		if err := p.before(ctx, q, args); err != nil {
			return pgconn.CommandTag{}, err
		}
	}
	tag, err := p.Executor.Exec(ctx, q, args...)
	if err == nil && p.after != nil {
		err = p.after(ctx, q, args)
	}
	return tag, err
}
func pauseWriter(t *testing.T) (chan struct{}, chan struct{}, func()) {
	t.Helper()
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	resume := func() { once.Do(func() { close(release) }) }
	t.Cleanup(resume)
	return reached, release, resume
}
func reachedWrite(t *testing.T, reached <-chan struct{}) {
	t.Helper()
	select {
	case <-reached:
	case <-time.After(3 * time.Second):
		t.Fatal("write barrier not reached")
	}
}
func pauseAt(ctx context.Context, reached chan<- struct{}, release <-chan struct{}) error {
	close(reached)
	select {
	case <-release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestIntegrationFirstCreationRoundTrip(t *testing.T) {
	for _, tc := range []struct{ name, start, end string }{{"historical", "2020-02-29", "2020-03-02"}, {"range", "0001-01-01", "9999-12-31"}, {"absent", "", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			f := persistent(t, tc.name)
			input := captureInput()
			input.ContactName = "Zoë"
			input.Destination = "東京"
			input.TravelStart, input.TravelEnd = tc.start, tc.end
			var before, after time.Time
			if err := f.admin.QueryRow(context.Background(), "SELECT clock_timestamp()").Scan(&before); err != nil {
				t.Fatal(err)
			}
			got, err := f.creator.Create(context.Background(), f.r, "request-key", input)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.admin.QueryRow(context.Background(), "SELECT clock_timestamp()").Scan(&after); err != nil {
				t.Fatal(err)
			}
			e, a := got.Enquiry, got.Audit
			if e.ID() != "persist-"+tc.name+"-1" || got.EventID != "persist-"+tc.name+"-2" || e.OrganizationID() != f.r.OrganizationID || e.CreatedBy() != f.r.ActorID || e.MembershipID() != f.r.MembershipID || e.Input() != input || e.State() != enquiries.StateNew || e.Version() != 1 || e.AssigneeMembershipID() != "" {
				t.Fatal("incorrect independently expected creation")
			}
			if a.Action != "enquiry.created" || a.ActorID != f.r.ActorID || a.MembershipID != f.r.MembershipID || a.OrganizationID != f.r.OrganizationID || a.EnquiryID != e.ID() || a.Capability != authz.CapabilityCreateEnquiry || !a.At.Equal(e.CreatedAt()) || a.At.Before(before) || a.At.After(after) || a.At.Nanosecond()%1000 != 0 {
				t.Fatal("wrong audit/time attribution")
			}
			if !e.Snapshot().LastChangedAt.Equal(a.At) {
				t.Fatal("initial change instant differs")
			}
			err = f.db.WithTx(context.Background(), pg.Scope{ActorID: f.r.ActorID, OrganizationID: f.r.OrganizationID}, func(ctx context.Context, tx pg.Executor) error {
				if err := restricted(ctx, tx, f.role); err != nil {
					return err
				}
				loaded, err := Load(ctx, tx, f.r.OrganizationID, e.ID())
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(loaded.Enquiry.Snapshot(), e.Snapshot()) || len(loaded.Transitions) != 0 || loaded.Enquiry.CreationAudit() != a {
					t.Fatal("round-trip mismatch")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			var version, expected int
			var fingerprint []byte
			var completed bool
			var enquiryID, eventID, actor, command string
			var completion time.Time
			err = f.admin.QueryRow(context.Background(), `SELECT fingerprint_version,fingerprint,completed,enquiry_id,event_id,actor_id,command,expected_version,completed_at::timestamptz FROM softteros_enquiries.enquiry_command_receipts WHERE organization_id=$1 AND membership_id=$2 AND request_key='request-key'`, f.r.OrganizationID, f.r.MembershipID).Scan(&version, &fingerprint, &completed, &enquiryID, &eventID, &actor, &command, &expected, &completion)
			if err != nil || version != 1 || len(fingerprint) != 32 || !completed || enquiryID != e.ID() || eventID != got.EventID || actor != f.r.ActorID || command != "enquiry.created" || expected != 0 || completion.Before(a.At) {
				t.Fatal("receipt mismatch", err)
			}
			proof, err := authz.NewContext(authz.ContextInput{Actor: authz.Actor{ID: f.r.ActorID, Authenticated: true}, ActiveOrganizationID: f.r.OrganizationID,
				Membership: authz.Membership{ID: f.r.MembershipID, ActorID: f.r.ActorID, OrganizationID: f.r.OrganizationID, Active: true, ValidFrom: a.At.Add(-time.Hour), ValidUntil: a.At.Add(time.Hour), Capabilities: []authz.Capability{authz.CapabilityCreateEnquiry}}}).AuthorizeEnquiryCreation(a.At)
			if err != nil {
				t.Fatal(err)
			}
			wantFingerprint, err := creationFingerprint(f.key, proof, "request-key", input)
			if err != nil || !bytes.Equal(fingerprint, wantFingerprint[:]) {
				t.Fatal("stored fingerprint differs from expected validated bindings/input", err)
			}
			creationCounts(t, f, [3]int{1, 1, 1})
			// Requesting a foreign resource in a different valid scope is unavailable.
			err = f.db.WithTx(context.Background(), pg.Scope{ActorID: "actor-1", OrganizationID: "org-2"}, func(ctx context.Context, tx pg.Executor) error {
				if err := restricted(ctx, tx, f.role); err != nil {
					return err
				}
				loaded, err := Load(ctx, tx, f.r.OrganizationID, e.ID())
				if !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(loaded, Loaded{}) {
					t.Fatal("cross-tenant existence leaked", err)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIntegrationFirstCreationDenialsAndDuplicateKeys(t *testing.T) {
	for _, mode := range []string{"capability", "identity", "cross-tenant", "invalid-input"} {
		t.Run(mode, func(t *testing.T) {
			f := persistent(t, "denial-"+mode)
			r := f.r
			input := captureInput()
			want := authz.ErrUnauthorized
			switch mode {
			case "capability":
				tx := f.writer(t, f.admin, false)
				revokeCapability(t, f.creationFixture, tx)
				commitAuthority(t, tx)
			case "identity":
				tx := f.writer(t, f.admin, true)
				f.identity.enabled.Store(false)
				commitAuthority(t, tx)
			case "cross-tenant":
				r.OrganizationID = "org-2"
			case "invalid-input":
				input.TravelEnd = ""
				want = enquiries.ErrInvalidInput
			}
			got, err := f.creator.Create(context.Background(), r, "key", input)
			noCreated(t, creationCompletion{got, err}, want)
			if f.ids.Load() != 0 {
				t.Fatal("denial called identifier provider")
			}
			creationCounts(t, f, [3]int{})
		})
	}
	f := persistent(t, "duplicates")
	original, err := f.creator.Create(context.Background(), f.r, "key", captureInput())
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []bool{false, true} {
		input := captureInput()
		if changed {
			input.Destination = "Sweden"
		}
		got, err := f.creator.Create(context.Background(), f.r, "key", input)
		noCreated(t, creationCompletion{got, err}, ErrDuplicateCreation)
		if f.ids.Load() != 2 {
			t.Fatal("duplicate called identifier provider")
		}
		creationCounts(t, f, [3]int{1, 1, 1})
	}
	// Equal input with a new scoped key is allowed; no invented business deduplication.
	if _, err = f.creator.Create(context.Background(), f.r, "other-key", captureInput()); err != nil {
		t.Fatal(err)
	}
	creationCounts(t, f, [3]int{2, 2, 2})
	var input string
	if err = f.admin.QueryRow(context.Background(), "SELECT destination FROM softteros_enquiries.enquiries WHERE organization_id=$1 AND enquiry_id=$2", f.r.OrganizationID, original.Enquiry.ID()).Scan(&input); err != nil || input != "Norway" {
		t.Fatal("duplicate altered original", err)
	}
}

func TestIntegrationFirstCreationRollbackAndCancellation(t *testing.T) {
	for _, stage := range []string{"before-enquiry", "before-event", "before-completion", "before-integrity", "cancel"} {
		t.Run(stage, func(t *testing.T) {
			f := persistent(t, "rollback-"+stage)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var beforePID uint32
			f.creator.authority.db = creationFixtureBoundary{db: f.db, role: f.role, wrap: func(e pg.Executor) pg.Executor {
				return &persistentObserved{Executor: e, before: func(ctx context.Context, q string, _ []any) error {
					if q == reserveCreationSQL {
						if err := e.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&beforePID); err != nil {
							return err
						}
					}
					target := map[string]string{"before-enquiry": insertCreationSQL, "before-event": insertCreationEventSQL, "before-completion": completeCreationSQL, "before-integrity": creationIntegritySQL}[stage]
					if q == target {
						_, err := e.Exec(ctx, "SELECT 1/0")
						return err
					}
					return nil
				}, after: func(_ context.Context, q string, _ []any) error {
					if stage == "cancel" && q == insertCreationSQL {
						cancel()
					}
					return nil
				}}
			}}
			got, err := f.creator.Create(ctx, f.r, "key", captureInput())
			noCreated(t, creationCompletion{got, err}, ErrStorage)
			if errors.Is(err, pg.ErrCleanup) {
				t.Fatal("healthy rollback cleanup failed", err)
			}
			if stage == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost")
			}
			creationCounts(t, f, [3]int{})
			var afterPID uint32
			err = f.db.WithTx(context.Background(), pg.Scope{ActorID: f.r.ActorID, OrganizationID: f.r.OrganizationID}, func(ctx context.Context, e pg.Executor) error {
				if err := restricted(ctx, e, f.role); err != nil {
					return err
				}
				return e.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&afterPID)
			})
			if err != nil || beforePID != afterPID {
				t.Fatal("healthy backend was not cleaned/reused", err)
			}
			f.creator.authority.db = creationFixtureBoundary{db: f.db, role: f.role}
			if _, err = f.creator.Create(context.Background(), f.r, "key", captureInput()); err != nil {
				t.Fatal("rolled-back receipt key not released", err)
			}
			creationCounts(t, f, [3]int{1, 1, 1})
		})
	}
}

func TestIntegrationFirstCreationConcurrentKeys(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		name := "commit"
		if rollback {
			name = "rollback"
		}
		t.Run(name, func(t *testing.T) {
			f := persistent(t, "compete-"+name)
			peer := peerCreator(t, f)
			paused, release, resume := pauseWriter(t)
			f.creator.authority.db = creationFixtureBoundary{db: f.db, role: f.role, wrap: func(e pg.Executor) pg.Executor {
				return &persistentObserved{Executor: e, after: func(ctx context.Context, q string, _ []any) error {
					if q == reserveCreationSQL {
						if err := pauseAt(ctx, paused, release); err != nil {
							return err
						}
						if rollback {
							return errors.New("synthetic reservation rollback")
						}
					}
					return nil
				}}
			}}
			first := startCreation(f.creator, f.r, "shared-key", captureInput(), context.Background())
			reachedWrite(t, paused)
			pid := make(chan uint32, 1)
			boundary := peer.authority.db.(creationFixtureBoundary)
			boundary.wrap = func(e pg.Executor) pg.Executor {
				return &persistentObserved{Executor: e, before: func(ctx context.Context, q string, _ []any) error {
					if q == reserveCreationSQL {
						var p uint32
						if err := e.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&p); err != nil {
							return err
						}
						pid <- p
					}
					return nil
				}}
			}
			peer.authority.db = boundary
			second := startCreation(peer, f.r, "shared-key", captureInput(), context.Background())
			waitAuthorityLock(t, f.admin, authorityPID(t, pid))
			var releaseAt time.Time
			if err := f.admin.QueryRow(context.Background(), "SELECT clock_timestamp()").Scan(&releaseAt); err != nil {
				t.Fatal(err)
			}
			resume()
			one, two := completedCreation(t, first), completedCreation(t, second)
			if rollback {
				noCreated(t, one, ErrStorage)
				if two.err != nil || two.result.Enquiry.CreatedAt().Before(releaseAt) {
					t.Fatal("waiter used stale time or failed after reservation rollback", two.err)
				}
			} else {
				if one.err != nil {
					t.Fatal(one.err)
				}
				noCreated(t, two, ErrDuplicateCreation)
			}
			creationCounts(t, f, [3]int{1, 1, 1})
		})
	}
}

func TestIntegrationFirstCreationExpiryAfterIntegrity(t *testing.T) {
	f := persistent(t, "final-expiry")
	writer := f.writer(t, f.admin, false)
	execAuthority(t, writer, "UPDATE softteros_access.memberships SET valid_until=clock_timestamp()+interval '2 seconds' WHERE organization_id=$1 AND membership_id=$2", f.r.OrganizationID, f.r.MembershipID)
	commitAuthority(t, writer)
	paused, release, resume := pauseWriter(t)
	f.creator.authority.db = creationFixtureBoundary{db: f.db, role: f.role, wrap: func(e pg.Executor) pg.Executor {
		return &persistentObserved{Executor: e, after: func(ctx context.Context, q string, _ []any) error {
			if q == creationIntegritySQL {
				return pauseAt(ctx, paused, release)
			}
			return nil
		}}
	}}
	done := startCreation(f.creator, f.r, "key", captureInput(), context.Background())
	reachedWrite(t, paused)
	// Separate transaction cannot see the fully written, still-uncommitted rows.
	creationCounts(t, f, [3]int{})
	waitAuthorityExpiry(t, f.creationFixture)
	resume()
	noCreated(t, completedCreation(t, done), authz.ErrUnauthorized)
	creationCounts(t, f, [3]int{})
}

func TestIntegrationFirstCreationRevocationFirst(t *testing.T) {
	for _, actor := range []bool{false, true} {
		name := "capability"
		if actor {
			name = "actor"
		}
		t.Run(name, func(t *testing.T) {
			f := persistent(t, "revoke-first-"+name)
			writer := f.writer(t, f.admin, actor)
			pid := make(chan uint32, 1)
			f.creator.authority.db = creationFixtureBoundary{db: f.db, role: f.role, wrap: func(e pg.Executor) pg.Executor { return &creationObserved{Executor: e, pid: pid} }}
			done := startCreation(f.creator, f.r, "key", captureInput(), context.Background())
			waitAuthorityLock(t, f.admin, authorityPID(t, pid))
			if f.identity.calls.Load() != 0 || f.ids.Load() != 0 {
				t.Fatal("pre-wait identity/ID work")
			}
			if actor {
				f.identity.enabled.Store(false)
			} else {
				revokeCapability(t, f.creationFixture, writer)
			}
			commitAuthority(t, writer)
			noCreated(t, completedCreation(t, done), authz.ErrUnauthorized)
			creationCounts(t, f, [3]int{})
		})
	}
}

// Test-only writer: exclusive actor then organization fences and revision updates,
// bounded connection settings plus a whole operation deadline. No production API.
func revokeAfterFences(ctx context.Context, conn *pgx.Conn, f *persistentFixture) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, end := context.WithTimeout(context.Background(), 3*time.Second)
		defer end()
		_ = tx.Rollback(cleanup)
	}()
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
			return err
		}
	}
	return tx.Commit(ctx)
}
func TestIntegrationFirstCreationBusinessFirst(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		name := "commit"
		if rollback {
			name = "rollback"
		}
		t.Run(name, func(t *testing.T) {
			f := persistent(t, "business-first-"+name)
			paused, release, resume := pauseWriter(t)
			f.creator.authority.db = creationFixtureBoundary{db: f.db, role: f.role, wrap: func(e pg.Executor) pg.Executor {
				return &persistentObserved{Executor: e, after: func(ctx context.Context, q string, _ []any) error {
					if q == creationIntegritySQL {
						if err := pauseAt(ctx, paused, release); err != nil {
							return err
						}
						if rollback {
							return errors.New("synthetic post-integrity rollback")
						}
					}
					return nil
				}}
			}}
			done := startCreation(f.creator, f.r, "key", captureInput(), context.Background())
			reachedWrite(t, paused)
			ctx, end := context.WithTimeout(context.Background(), 3*time.Second)
			defer end()
			writer, err := pgx.ConnectConfig(ctx, f.admin.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_ = writer.Close(cleanup)
			}()
			var pid uint32
			if err = writer.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
				t.Fatal(err)
			}
			writerDone := make(chan error, 1)
			go func() { writerDone <- revokeAfterFences(ctx, writer, f) }()
			waitAuthorityLock(t, f.admin, pid)
			select {
			case err := <-writerDone:
				t.Fatal("revocation passed held business fences", err)
			default:
			}
			resume()
			result := completedCreation(t, done)
			if rollback {
				noCreated(t, result, ErrStorage)
			} else if result.err != nil {
				t.Fatal(result.err)
			}
			if err = authorityResult(t, writerDone); err != nil {
				t.Fatal("writer failed after business completion", err)
			}
			f.creator.authority.db = creationFixtureBoundary{db: f.db, role: f.role}
			got, err := f.creator.Create(context.Background(), f.r, "later-key", captureInput())
			noCreated(t, creationCompletion{got, err}, authz.ErrUnauthorized)
			if rollback {
				creationCounts(t, f, [3]int{})
			} else {
				creationCounts(t, f, [3]int{1, 1, 1})
			}
		})
	}
}
