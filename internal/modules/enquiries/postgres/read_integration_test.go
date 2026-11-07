package postgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries/application"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type assignedReadFixture struct {
	*persistentFixture
	request application.ReadRequest
	record  storedEnquiry
	history []storedEvent
}

func newAssignedReadFixture(t *testing.T, name string, version int) *assignedReadFixture {
	t.Helper()
	f := persistent(t, "assigned-"+name)
	request := application.ReadRequest{ActorID: f.r.ActorID, OrganizationID: f.r.OrganizationID,
		MembershipID: f.r.MembershipID, RequestID: "get-" + name}
	record, history := namedFixture(3, "assigned-read", request.OrganizationID)
	record.Input.Destination = "Destination " + name
	if version == 3 {
		record.Start, record.End = pgtype.Date{}, pgtype.Date{}
	}
	for i := 1; i < len(history); i++ {
		history[i].ActorID, history[i].MembershipID = request.ActorID, request.MembershipID
		history[i].Assignee = text(request.MembershipID)
		if i == 2 {
			history[i].PreviousAssignee = history[i].Assignee
		}
	}
	seed(t, f.admin, record, history[:version])
	writer := f.writer(t, f.admin, false)
	execAuthority(t, writer, `INSERT INTO softteros_access.membership_enquiry_capabilities VALUES($1,$2,'enquiries.read')`,
		request.OrganizationID, request.MembershipID)
	commitAuthority(t, writer)
	return &assignedReadFixture{persistentFixture: f, request: request, record: record, history: history}
}

func validReadAttestation(r application.ReadRequest) ReadAttestation {
	return ReadAttestation{Actor: authz.Actor{ID: r.ActorID, Authenticated: true, Human: true}, RequestID: r.RequestID}
}

func (f *assignedReadFixture) reader(t *testing.T, request application.ReadRequest, observe func(pg.Executor) pg.Executor) *AssignedReader {
	t.Helper()
	identity := readIdentityFunc(func(ctx context.Context, r ReadIdentityRequest) (ReadAttestation, error) {
		if err := ctx.Err(); err != nil {
			return ReadAttestation{}, err
		}
		if r != (ReadIdentityRequest{ActorID: request.ActorID, RequestID: request.RequestID}) {
			return ReadAttestation{}, errors.New("wrong fixture actor/request")
		}
		return validReadAttestation(request), nil
	})
	reader, err := NewAssignedReader(f.db, identity)
	if err != nil {
		t.Fatal(err)
	}
	boundary := creationFixtureBoundary{db: f.db, role: f.role, wrap: observe}
	reader.db = boundary
	if observe != nil {
		// Allow time to observe lock waits and cross the database expiry
		// boundary without changing production budgets or server settings.
		reader.db = readBoundaryFunc(func(ctx context.Context, scope pg.Scope, callback func(context.Context, pg.Executor) error) error {
			return boundary.WithTx(ctx, scope, func(ctx context.Context, tx pg.Executor) error {
				if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout='5s'"); err != nil {
					return err
				}
				return callback(ctx, tx)
			})
		})
	}
	return reader
}

func requireUnavailableRead(t *testing.T, view application.EnquiryDetails, err error) {
	t.Helper()
	if view != (application.EnquiryDetails{}) || err != application.ErrEnquiryUnavailable {
		t.Fatal("read did not return the uniform empty unavailable result", err)
	}
}

func TestIntegrationAssignedEnquiryReadAccessAndProjection(t *testing.T) {
	first := newAssignedReadFixture(t, "first", 2)
	second := newAssignedReadFixture(t, "second", 3)
	ctx := context.Background()
	// A real newly created enquiry remains outside the assigned read surface.
	captured, err := first.creator.Create(ctx, first.r, "assigned-read-new", captureInput())
	if err != nil {
		t.Fatal("creation positive control", err)
	}
	foreign, events := namedFixture(2, "assigned-foreign-only", second.request.OrganizationID)
	// An eligible-looking foreign row can carry the same membership ID text.
	events[1].ActorID, events[1].MembershipID = second.request.ActorID, first.request.MembershipID
	events[1].Assignee = text(first.request.MembershipID)
	seed(t, second.admin, foreign, events)
	before := recoverySnapshot(t, first.persistentFixture)
	for _, tc := range []struct {
		fixture *assignedReadFixture
		want    application.EnquiryDetails
	}{
		{first, application.EnquiryDetails{EnquiryID: "load-assigned-read", State: enquiries.StateUnderReview, Version: 2,
			Destination: "Destination first", TravellerCount: 3, TravelStart: "2020-02-29", TravelEnd: "2020-03-02"}},
		{second, application.EnquiryDetails{EnquiryID: "load-assigned-read", State: enquiries.StateQualified, Version: 3,
			Destination: "Destination second", TravellerCount: 3}},
	} {
		f := tc.fixture
		reader := f.reader(t, f.request, nil)
		got, err := reader.GetEnquiry(ctx, f.request, "load-assigned-read")
		if got != tc.want || err != nil {
			t.Fatal("authorized read lost tenant, state, version or projected trip fields", err)
		}
	}

	// Independent effective-role query metadata checks the storage projection,
	// alongside the unit test of the Go result field allowlist.
	err = first.db.WithTx(ctx, pg.Scope{ActorID: first.request.ActorID, OrganizationID: first.request.OrganizationID},
		func(ctx context.Context, tx pg.Executor) error {
			if err := restricted(ctx, tx, first.role); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, assignedTripSQL, first.request.OrganizationID, first.record.ID)
			if err != nil {
				return err
			}
			defer rows.Close()
			var fields []string
			for _, field := range rows.FieldDescriptions() {
				fields = append(fields, field.Name)
			}
			if !reflect.DeepEqual(fields, []string{"destination", "traveller_count", "travel_start", "travel_end"}) || !rows.Next() {
				return errors.New("assigned trip query projection or positive row changed")
			}
			return rows.Err()
		})
	if err != nil {
		t.Fatal(err)
	}

	// The same actor with a different valid entitled membership is not the
	// exact assignee. Other actor and tenant attempts have valid attestations.
	otherMembership := first.request
	otherMembership.MembershipID = "second-membership"
	writer := first.writer(t, first.admin, false)
	execAuthority(t, writer, `INSERT INTO softteros_access.memberships VALUES($1,$2,$3,true,false,'2000-01-01+00','9999-01-01+00')`,
		otherMembership.OrganizationID, otherMembership.MembershipID, otherMembership.ActorID)
	execAuthority(t, writer, `INSERT INTO softteros_access.membership_enquiry_capabilities VALUES($1,$2,'enquiries.read')`,
		otherMembership.OrganizationID, otherMembership.MembershipID)
	commitAuthority(t, writer)
	otherActor, otherOrganization := first.request, first.request
	otherActor.ActorID = second.request.ActorID
	otherOrganization.OrganizationID = second.request.OrganizationID
	for _, tc := range []struct {
		name    string
		request application.ReadRequest
		id      string
	}{
		{"new", first.request, captured.Enquiry.ID()},
		{"missing", first.request, "no-assigned-enquiry"},
		{"other tenant record", first.request, foreign.ID},
		{"other organization", otherOrganization, first.record.ID},
		{"other actor", otherActor, first.record.ID},
		{"another membership of the assignee actor", otherMembership, first.record.ID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := first.reader(t, tc.request, nil)
			got, err := reader.GetEnquiry(ctx, tc.request, tc.id)
			requireUnavailableRead(t, got, err)
		})
	}
	if after := recoverySnapshot(t, first.persistentFixture); before != after {
		t.Fatal("assigned reads modified business, event or receipt records")
	}
}

func TestIntegrationAssignedEnquiryReadCurrentAuthority(t *testing.T) {
	f := newAssignedReadFixture(t, "current-authority", 2)
	ctx := context.Background()
	reader := f.reader(t, f.request, nil)
	good := reader.identity
	for _, tc := range []struct {
		name   string
		change func(*ReadAttestation)
	}{
		{"disabled", func(a *ReadAttestation) { a.Actor.Authenticated = false }},
		{"nonhuman", func(a *ReadAttestation) { a.Actor.Human = false }},
		{"wrong actor", func(a *ReadAttestation) { a.Actor.ID = "other-actor" }},
		{"wrong request", func(a *ReadAttestation) { a.RequestID = "old-request" }},
		{"absent attestation", func(a *ReadAttestation) { *a = ReadAttestation{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader.identity = readIdentityFunc(func(context.Context, ReadIdentityRequest) (ReadAttestation, error) {
				a := validReadAttestation(f.request)
				tc.change(&a)
				return a, nil
			})
			got, err := reader.GetEnquiry(ctx, f.request, f.record.ID)
			requireUnavailableRead(t, got, err)
		})
	}
	reader.identity = good
	writer := f.writer(t, f.admin, false)
	execAuthority(t, writer, removeReadEntitlement, f.request.OrganizationID, f.request.MembershipID)
	execAuthority(t, writer, `INSERT INTO softteros_access.membership_enquiry_capabilities
VALUES ($1,$2,'enquiries.review'),($1,$2,'enquiries.qualify')`, f.request.OrganizationID, f.request.MembershipID)
	commitAuthority(t, writer)
	got, err := reader.GetEnquiry(ctx, f.request, f.record.ID)
	requireUnavailableRead(t, got, err)
	administrator := f.reader(t, f.request, nil)
	administrator.db = f.db
	got, err = administrator.GetEnquiry(ctx, f.request, f.record.ID)
	requireUnavailableRead(t, got, err)

	writer = f.writer(t, f.admin, false)
	execAuthority(t, writer, `INSERT INTO softteros_access.membership_enquiry_capabilities VALUES($1,$2,'enquiries.read')`,
		f.request.OrganizationID, f.request.MembershipID)
	commitAuthority(t, writer)
	if got, err := reader.GetEnquiry(ctx, f.request, f.record.ID); err != nil || got.EnquiryID != f.record.ID {
		t.Fatal("restoring the exact entitlement did not restore otherwise valid read access", err)
	}
	for _, tc := range []struct{ name, fields string }{
		{"inactive", "active=false"},
		{"revoked", "revoked=true"},
		{"expired", "valid_until=clock_timestamp()"},
		{"premature", "valid_from=clock_timestamp()+interval '1 hour'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := f.writer(t, f.admin, false)
			execAuthority(t, tx, `UPDATE softteros_access.memberships
SET active=true,revoked=false,valid_from='2000-01-01+00',valid_until='9999-01-01+00'
WHERE organization_id=$1 AND membership_id=$2`, f.request.OrganizationID, f.request.MembershipID)
			execAuthority(t, tx, "UPDATE softteros_access.memberships SET "+tc.fields+" WHERE organization_id=$1 AND membership_id=$2",
				f.request.OrganizationID, f.request.MembershipID)
			commitAuthority(t, tx)
			got, err := reader.GetEnquiry(ctx, f.request, f.record.ID)
			requireUnavailableRead(t, got, err)
		})
	}
}

const removeReadEntitlement = `DELETE FROM softteros_access.membership_enquiry_capabilities
WHERE organization_id=$1 AND membership_id=$2 AND capability='enquiries.read'`

type readQueryHook func(context.Context, string, pg.Executor) error

type observedAssignedRead struct {
	pg.Executor
	before, after readQueryHook
}

func (o observedAssignedRead) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	if o.before != nil {
		if err := o.before(ctx, query, o.Executor); err != nil {
			return creationRow(func(...any) error { return err })
		}
	}
	row := o.Executor.QueryRow(ctx, query, args...)
	if o.after == nil {
		return row
	}
	return creationRow(func(dest ...any) error {
		if err := row.Scan(dest...); err != nil {
			return err
		}
		return o.after(ctx, query, o.Executor)
	})
}

func observeAssignedRead(before, after readQueryHook) func(pg.Executor) pg.Executor {
	return func(e pg.Executor) pg.Executor {
		return observedAssignedRead{Executor: e, before: before, after: after}
	}
}

func assignedReadPID(query string, pid chan<- uint32) readQueryHook {
	return func(ctx context.Context, q string, tx pg.Executor) error {
		if q != query {
			return nil
		}
		var backend uint32
		if err := tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&backend); err != nil {
			return err
		}
		select {
		case pid <- backend:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func waitAssignedBlocked(t *testing.T, observer *pgx.Conn, waiting, blocker uint32) {
	t.Helper()
	ctx, end := context.WithTimeout(context.Background(), 3*time.Second)
	defer end()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		err := observer.QueryRow(ctx, "SELECT $2::integer=ANY(pg_blocking_pids($1::integer))", waiting, blocker).Scan(&blocked)
		if err != nil {
			t.Fatal("observe real assigned-read lock wait", err)
		}
		if blocked {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("backend %d did not wait for %d", waiting, blocker)
		}
	}
}

func assignedReadPeer(t *testing.T, f *assignedReadFixture) *pgx.Conn {
	t.Helper()
	cfg := f.admin.Config().Copy()
	cfg.RuntimeParams["lock_timeout"] = "5000"
	ctx, end := context.WithTimeout(context.Background(), 5*time.Second)
	defer end()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal("assigned-read fixture connection", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := conn.Close(cleanup); err != nil {
			t.Error("close assigned-read fixture connection", err)
		}
	})
	return conn
}

type assignedReadCompletion struct {
	view application.EnquiryDetails
	err  error
}

func startAssignedReadWork[T any](t *testing.T, work func() T) <-chan T {
	t.Helper()
	result := make(chan T, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		result <- work()
	}()
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("assigned-read fixture worker did not finish")
		}
	})
	return result
}

func (f *assignedReadFixture) startRead(t *testing.T, ctx context.Context, reader *AssignedReader) <-chan assignedReadCompletion {
	t.Helper()
	return startAssignedReadWork(t, func() assignedReadCompletion {
		view, err := reader.GetEnquiry(ctx, f.request, f.record.ID)
		return assignedReadCompletion{view, err}
	})
}

func completedAssignedRead(t *testing.T, done <-chan assignedReadCompletion) assignedReadCompletion {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(6 * time.Second):
		t.Fatal("assigned read did not finish")
		return assignedReadCompletion{}
	}
}

func TestIntegrationAssignedEnquiryReadRevocationOrdering(t *testing.T) {
	t.Run("revocation first", func(t *testing.T) {
		f := newAssignedReadFixture(t, "revoke-first", 2)
		observer := assignedReadPeer(t, f)
		writer := f.writer(t, f.admin, false)
		execAuthority(t, writer, removeReadEntitlement, f.request.OrganizationID, f.request.MembershipID)
		pid := make(chan uint32, 1)
		reader := f.reader(t, f.request, observeAssignedRead(assignedReadPID(creationFenceSQL, pid), nil))
		attested := make(chan struct{}, 1)
		identity := reader.identity
		reader.identity = readIdentityFunc(func(ctx context.Context, r ReadIdentityRequest) (ReadAttestation, error) {
			attested <- struct{}{}
			return identity.CurrentEnquiryRead(ctx, r)
		})
		ctx, end := context.WithTimeout(context.Background(), 12*time.Second)
		defer end()
		done := f.startRead(t, ctx, reader)
		waitAssignedBlocked(t, observer, authorityPID(t, pid), f.admin.PgConn().PID())
		select {
		case <-attested:
			t.Fatal("identity attested before authority fences were acquired")
		default:
		}
		commitAuthority(t, writer)
		result := completedAssignedRead(t, done)
		requireUnavailableRead(t, result.view, result.err)
		select {
		case <-attested:
		default:
			t.Fatal("post-wait request was not attested")
		}
	})
	t.Run("read first", func(t *testing.T) {
		f := newAssignedReadFixture(t, "read-before-revoke", 2)
		writer := assignedReadPeer(t, f)
		paused, release, resume := pauseWriter(t)
		pid := make(chan uint32, 1)
		reader := f.reader(t, f.request, observeAssignedRead(assignedReadPID(assignedTripSQL, pid),
			func(ctx context.Context, q string, _ pg.Executor) error {
				if q == assignedTripSQL {
					return pauseAt(ctx, paused, release)
				}
				return nil
			}))
		ctx, end := context.WithTimeout(context.Background(), 12*time.Second)
		defer end()
		done := f.startRead(t, ctx, reader)
		reachedWrite(t, paused)
		readerPID := authorityPID(t, pid)
		writerDone := startAssignedReadWork(t, func() error {
			return revokeAfterFences(ctx, writer, f.persistentFixture, authz.CapabilityReadEnquiry)
		})
		waitAssignedBlocked(t, f.admin, writer.PgConn().PID(), readerPID)
		resume()
		result := completedAssignedRead(t, done)
		if result.err != nil || result.view.State != enquiries.StateUnderReview || result.view.Version != 2 {
			t.Fatal("fenced read ordered first did not complete", result.err)
		}
		if err := authorityResult(t, writerDone); err != nil {
			t.Fatal("revocation did not commit after reader release", err)
		}
		plain := f.reader(t, f.request, nil)
		view, err := plain.GetEnquiry(ctx, f.request, f.record.ID)
		requireUnavailableRead(t, view, err)
	})
}

func beginAssignedFixtureTx(t *testing.T, conn *pgx.Conn) pgx.Tx {
	t.Helper()
	ctx, end := context.WithTimeout(context.Background(), 4*time.Second)
	defer end()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	})
	return tx
}

func (f *assignedReadFixture) prepareTransition(t *testing.T, index int) storedEvent {
	t.Helper()
	event := f.history[index]
	writer := f.writer(t, f.admin, false)
	execAuthority(t, writer, "INSERT INTO softteros_access.membership_enquiry_capabilities VALUES($1,$2,$3)",
		event.OrganizationID, event.MembershipID, event.Capability)
	execAuthority(t, writer, `INSERT INTO softteros_access.enquiry_transition_grants VALUES
($1,$2,$3,$4,$5,$6,true,false,'2000-01-01+00','9999-01-01+00')`,
		event.OrganizationID, event.Grant, event.ActorID, event.MembershipID, event.EnquiryID, event.Capability)
	commitAuthority(t, writer)
	return event
}

// Exercise an actual supported row update with valid history under the
// restricted role. This is synthetic fixture SQL, not a transition adapter.
func applyAssignedFixtureTransition(ctx context.Context, tx pgx.Tx, role string, event storedEvent) error {
	if err := restricted(ctx, tx, role); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('softteros.actor_id',$1,true),set_config('softteros.organization_id',$2,true)",
		event.ActorID, event.OrganizationID); err != nil {
		return err
	}
	actor, organization, err := lockAuthority(ctx, tx, event.ActorID, event.OrganizationID)
	if err != nil {
		return err
	}
	if actor <= 0 || organization <= 0 {
		return errors.New("fixture transition did not acquire authority fences")
	}
	return advanceWithGrant(ctx, tx, event)
}

func TestIntegrationAssignedEnquiryReadRowOrdering(t *testing.T) {
	t.Run("assignment becomes visible on commit", func(t *testing.T) {
		f := newAssignedReadFixture(t, "claim", 1)
		event := f.prepareTransition(t, 1)
		writer := beginAssignedFixtureTx(t, f.admin)
		ctx, end := context.WithTimeout(context.Background(), 12*time.Second)
		defer end()
		if err := applyAssignedFixtureTransition(ctx, writer, f.role, event); err != nil {
			t.Fatal("valid uncommitted claim fixture", err)
		}
		reader := f.reader(t, f.request, nil)
		view, err := reader.GetEnquiry(ctx, f.request, f.record.ID)
		requireUnavailableRead(t, view, err)
		commitAuthority(t, writer)
		view, err = reader.GetEnquiry(ctx, f.request, f.record.ID)
		if err != nil || view.EnquiryID != f.record.ID || view.State != enquiries.StateUnderReview || view.Version != 2 {
			t.Fatal("committed current assignment was not readable", err)
		}
	})
	t.Run("reader waits for state change", func(t *testing.T) {
		f := newAssignedReadFixture(t, "state-before-read", 2)
		event := f.prepareTransition(t, 2)
		writerConn := assignedReadPeer(t, f)
		writer := beginAssignedFixtureTx(t, writerConn)
		ctx, end := context.WithTimeout(context.Background(), 12*time.Second)
		defer end()
		if err := applyAssignedFixtureTransition(ctx, writer, f.role, event); err != nil {
			t.Fatal("valid uncommitted qualification fixture", err)
		}
		pid := make(chan uint32, 1)
		reader := f.reader(t, f.request, observeAssignedRead(assignedReadPID(lockAssignedEnquirySQL, pid), nil))
		done := f.startRead(t, ctx, reader)
		waitAssignedBlocked(t, f.admin, authorityPID(t, pid), writerConn.PgConn().PID())
		commitAuthority(t, writer)
		result := completedAssignedRead(t, done)
		if result.err != nil || result.view.State != enquiries.StateQualified || result.view.Version != 3 {
			t.Fatal("read returned a pre-wait state or version", result.err)
		}
	})
	t.Run("state change waits for shared row lock", func(t *testing.T) {
		f := newAssignedReadFixture(t, "read-before-state", 2)
		event := f.prepareTransition(t, 2)
		writerConn := assignedReadPeer(t, f)
		writer := beginAssignedFixtureTx(t, writerConn)
		paused, release, resume := pauseWriter(t)
		pid := make(chan uint32, 1)
		reader := f.reader(t, f.request, observeAssignedRead(assignedReadPID(assignedTripSQL, pid),
			func(ctx context.Context, q string, _ pg.Executor) error {
				if q == assignedTripSQL {
					return pauseAt(ctx, paused, release)
				}
				return nil
			}))
		ctx, end := context.WithTimeout(context.Background(), 12*time.Second)
		defer end()
		done := f.startRead(t, ctx, reader)
		reachedWrite(t, paused)
		readerPID := authorityPID(t, pid)
		writerDone := startAssignedReadWork(t, func() error {
			if err := applyAssignedFixtureTransition(ctx, writer, f.role, event); err != nil {
				return err
			}
			return writer.Commit(ctx)
		})
		// The writer updates only non-key values. FOR KEY SHARE would not
		// block this update and therefore fails this positive wait assertion.
		waitAssignedBlocked(t, f.admin, writerConn.PgConn().PID(), readerPID)
		resume()
		result := completedAssignedRead(t, done)
		if result.err != nil || result.view.State != enquiries.StateUnderReview || result.view.Version != 2 {
			t.Fatal("reader ordered first did not keep one current version", result.err)
		}
		if err := authorityResult(t, writerDone); err != nil {
			t.Fatal("qualification did not commit after row lock release", err)
		}
		plain := f.reader(t, f.request, nil)
		view, err := plain.GetEnquiry(ctx, f.request, f.record.ID)
		if err != nil || view.State != enquiries.StateQualified || view.Version != 3 {
			t.Fatal("new read did not see the committed qualification", err)
		}
	})
}

func holdAssignedRow(t *testing.T, f *assignedReadFixture, conn *pgx.Conn) pgx.Tx {
	t.Helper()
	tx := beginAssignedFixtureTx(t, conn)
	ctx, end := context.WithTimeout(context.Background(), 4*time.Second)
	defer end()
	var id string
	err := tx.QueryRow(ctx, `SELECT enquiry_id::text FROM softteros_enquiries.enquiries
WHERE organization_id=$1 AND enquiry_id=$2 FOR UPDATE`, f.request.OrganizationID, f.record.ID).Scan(&id)
	if err != nil || id != f.record.ID {
		t.Fatal("test did not lock the exact enquiry row", err)
	}
	return tx
}

func expireAssignedReadSoon(t *testing.T, f *assignedReadFixture) {
	t.Helper()
	writer := f.writer(t, f.admin, false)
	execAuthority(t, writer, `UPDATE softteros_access.memberships SET valid_until=clock_timestamp()+interval '2 seconds'
WHERE organization_id=$1 AND membership_id=$2`, f.request.OrganizationID, f.request.MembershipID)
	commitAuthority(t, writer)
}

func TestIntegrationAssignedEnquiryReadExpiry(t *testing.T) {
	t.Run("while waiting for row lock", func(t *testing.T) {
		f := newAssignedReadFixture(t, "expiry-lock", 2)
		holderConn := assignedReadPeer(t, f)
		holder := holdAssignedRow(t, f, holderConn)
		pid := make(chan uint32, 1)
		capture := assignedReadPID(lockAssignedEnquirySQL, pid)
		queriedTrip := false
		reader := f.reader(t, f.request, observeAssignedRead(func(ctx context.Context, q string, tx pg.Executor) error {
			if q == assignedTripSQL {
				queriedTrip = true
			}
			return capture(ctx, q, tx)
		}, nil))
		ctx, end := context.WithTimeout(context.Background(), 12*time.Second)
		defer end()
		expireAssignedReadSoon(t, f)
		done := f.startRead(t, ctx, reader)
		waitAssignedBlocked(t, f.admin, authorityPID(t, pid), holderConn.PgConn().PID())
		waitAuthorityExpiry(t, f.creationFixture)
		commitAuthority(t, holder)
		result := completedAssignedRead(t, done)
		requireUnavailableRead(t, result.view, result.err)
		if queriedTrip {
			t.Fatal("expired membership reached trip projection after the wait")
		}
	})
	t.Run("after reading trip fields", func(t *testing.T) {
		f := newAssignedReadFixture(t, "expiry-final", 2)
		paused, release, resume := pauseWriter(t)
		reader := f.reader(t, f.request, observeAssignedRead(nil,
			func(ctx context.Context, q string, _ pg.Executor) error {
				if q == assignedTripSQL {
					return pauseAt(ctx, paused, release)
				}
				return nil
			}))
		ctx, end := context.WithTimeout(context.Background(), 12*time.Second)
		defer end()
		expireAssignedReadSoon(t, f)
		done := f.startRead(t, ctx, reader)
		reachedWrite(t, paused)
		waitAuthorityExpiry(t, f.creationFixture)
		resume()
		result := completedAssignedRead(t, done)
		requireUnavailableRead(t, result.view, result.err)
	})
}

func TestIntegrationAssignedEnquiryReadFailures(t *testing.T) {
	f := newAssignedReadFixture(t, "failures", 2)
	before := recoverySnapshot(t, f.persistentFixture)
	t.Run("cancel blocked read", func(t *testing.T) {
		holderConn := assignedReadPeer(t, f)
		holder := holdAssignedRow(t, f, holderConn)
		pid := make(chan uint32, 1)
		reader := f.reader(t, f.request, observeAssignedRead(assignedReadPID(lockAssignedEnquirySQL, pid), nil))
		ctx, end := context.WithTimeout(context.Background(), 12*time.Second)
		defer end()
		done := f.startRead(t, ctx, reader)
		waitAssignedBlocked(t, f.admin, authorityPID(t, pid), holderConn.PgConn().PID())
		end()
		result := completedAssignedRead(t, done)
		if result.view != (application.EnquiryDetails{}) || !errors.Is(result.err, context.Canceled) ||
			!errors.Is(result.err, application.ErrEnquiryReadFailed) || errors.Is(result.err, application.ErrEnquiryUnavailable) {
			t.Fatal("cancelled lock wait returned data or an incorrect error", result.err)
		}
		commitAuthority(t, holder)
	})
	t.Run("PostgreSQL query failure", func(t *testing.T) {
		var sqlstate string
		reader := f.reader(t, f.request, observeAssignedRead(func(ctx context.Context, q string, tx pg.Executor) error {
			if q != assignedTripSQL {
				return nil
			}
			// Cause a real server statement error on the transaction
			// connection at the projection boundary. No schema is altered.
			err := tx.QueryRow(ctx, "SELECT 1/0").Scan(new(int32))
			var server *pgconn.PgError
			if errors.As(err, &server) {
				sqlstate = server.Code
			}
			return err
		}, nil))
		view, err := reader.GetEnquiry(context.Background(), f.request, f.record.ID)
		if sqlstate != "22012" || view != (application.EnquiryDetails{}) ||
			!errors.Is(err, application.ErrEnquiryReadFailed) || !errors.Is(err, ErrStorage) ||
			errors.Is(err, application.ErrEnquiryUnavailable) || strings.Contains(err.Error(), "division by zero") ||
			strings.Contains(err.Error(), sqlstate) {
			t.Fatal("real storage failure was masked or exposed driver diagnostics", err)
		}
	})
	t.Run("identity source unavailable", func(t *testing.T) {
		reader := f.reader(t, f.request, nil)
		reader.identity = readIdentityFunc(func(context.Context, ReadIdentityRequest) (ReadAttestation, error) {
			return ReadAttestation{}, errors.New("private identity error")
		})
		view, err := reader.GetEnquiry(context.Background(), f.request, f.record.ID)
		if view != (application.EnquiryDetails{}) || !errors.Is(err, application.ErrEnquiryReadFailed) ||
			strings.Contains(err.Error(), "private identity error") {
			t.Fatal("identity source failure exposed data or diagnostics", err)
		}
	})
	t.Run("simulated completion error", func(t *testing.T) {
		reader := f.reader(t, f.request, nil)
		boundary := reader.db
		reader.db = readBoundaryFunc(func(ctx context.Context, scope pg.Scope, callback func(context.Context, pg.Executor) error) error {
			if err := boundary.WithTx(ctx, scope, callback); err != nil {
				return err
			}
			return pg.ErrCommitUnknown
		})
		view, err := reader.GetEnquiry(context.Background(), f.request, f.record.ID)
		if view != (application.EnquiryDetails{}) || !errors.Is(err, application.ErrEnquiryReadFailed) || !errors.Is(err, pg.ErrCommitUnknown) {
			t.Fatal("candidate escaped a transaction completion error", err)
		}
	})
	plain := f.reader(t, f.request, nil)
	if got, err := plain.GetEnquiry(context.Background(), f.request, f.record.ID); err != nil || got.EnquiryID != f.record.ID {
		t.Fatal("read did not recover after failed transactions", err)
	}
	if before != recoverySnapshot(t, f.persistentFixture) {
		t.Fatal("read failures changed business, event or receipt records")
	}
}
