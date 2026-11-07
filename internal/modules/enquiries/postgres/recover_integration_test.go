package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
)

const recoveryKey = "original-creation-key"

func recoveryAttempt(t *testing.T, f *persistentFixture, db *pg.DB, request CreationRequest) (*FirstCreator, *fixtureIdentity) {
	t.Helper()
	if request.RequestID == f.r.RequestID || request.RequestID == recoveryKey {
		t.Fatal("recovery fixture needs a separate attestation request ID")
	}
	identity := &fixtureIdentity{actor: request.ActorID, request: request.RequestID}
	identity.enabled.Store(true)
	c, err := NewFirstCreator(db, identity, f.key[:], f.creator.newID)
	if err != nil {
		t.Fatal(err)
	}
	c.authority.db = creationFixtureBoundary{db: db, role: f.role}
	return c, identity
}

func recoverySnapshot(t *testing.T, f *persistentFixture) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var snapshot string
	err := f.admin.QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(e) ORDER BY enquiry_id) FROM softteros_enquiries.enquiries e WHERE organization_id=$1),
 (SELECT jsonb_agg(to_jsonb(v) ORDER BY event_id) FROM softteros_enquiries.enquiry_events v WHERE organization_id=$1),
 (SELECT jsonb_agg(to_jsonb(r) ORDER BY membership_id,request_key) FROM softteros_enquiries.enquiry_command_receipts r WHERE organization_id=$1)
 )::text`, f.r.OrganizationID).Scan(&snapshot)
	if err != nil {
		t.Fatal("could not inspect synthetic records", err)
	}
	return snapshot // Compare in memory only. Do not print fingerprints or payloads.
}

func TestIntegrationCreationRecoveryHistoricalAcknowledgement(t *testing.T) {
	f := persistent(t, "recover-history")
	input := captureInput()
	input.ContactName, input.Destination = "Zoë", "東京"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Simulate losing the acknowledgement only after a real successful commit.
	// This does not inject a network fault or change the production boundary.
	boundary := f.creator.authority.db
	f.creator.authority.db = recoveryBoundaryFunc(func(ctx context.Context, scope pg.Scope, fn func(context.Context, pg.Executor) error) error {
		if err := boundary.WithTx(ctx, scope, fn); err != nil {
			return err
		}
		return pg.ErrCommitUnknown
	})
	lost, err := f.creator.Create(ctx, f.r, recoveryKey, input)
	noCreated(t, creationCompletion{lost, err}, pg.ErrCommitUnknown)
	f.creator.authority.db = boundary
	creationCounts(t, f, [3]int{1, 1, 1})
	want := RecoveredCreation{OrganizationID: f.r.OrganizationID, EnquiryID: "persist-recover-history-1",
		EventID: "persist-recover-history-2", Action: "enquiry.created", Version: 1}
	if err = f.admin.QueryRow(ctx, `SELECT at::timestamptz FROM softteros_enquiries.enquiry_events
 WHERE organization_id=$1 AND event_id=$2 AND action='enquiry.created'`, want.OrganizationID, want.EventID).Scan(&want.At); err != nil {
		t.Fatal("original event missing", err)
	}
	want.At = want.At.UTC()
	r := f.r
	r.RequestID = "recover-before-review"
	c, identity := recoveryAttempt(t, f, f.db, r)
	got, err := c.Recover(ctx, r, recoveryKey, input)
	if err != nil || got != want || identity.calls.Load() != 1 {
		t.Fatal("recovery of committed creation did not use the fresh attestation and original key", err)
	}

	// Commit later history using the existing test-only SQL fixture. Its review
	// receipt shares the original actor and membership, but is a different command.
	_, history := namedFixture(2, "recovery-later", f.r.OrganizationID)
	review := history[1]
	review.EnquiryID, review.ActorID, review.MembershipID = want.EnquiryID, f.r.ActorID, f.r.MembershipID
	review.Assignee, review.At = text(f.r.MembershipID), stamp(want.At.Add(time.Microsecond))
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, end := context.WithTimeout(context.Background(), 3*time.Second)
		defer end()
		_ = tx.Rollback(cleanup)
	}()
	if err = advance(ctx, tx, review); err != nil {
		t.Fatal("later review fixture", err)
	}
	commitAuthority(t, tx)
	var state string
	var version int64
	if err = f.admin.QueryRow(ctx, `SELECT state,version FROM softteros_enquiries.enquiries
 WHERE organization_id=$1 AND enquiry_id=$2`, want.OrganizationID, want.EnquiryID).Scan(&state, &version); err != nil || state != "Under review" || version != 2 {
		t.Fatal("positive control: enquiry did not advance", err)
	}
	before := recoverySnapshot(t, f)
	for _, attempt := range []string{"recover-after-review", "recover-after-review-again"} {
		r.RequestID = attempt
		c, identity = recoveryAttempt(t, f, f.db, r)
		got, err = c.Recover(ctx, r, recoveryKey, input)
		if err != nil || got != want || identity.calls.Load() != 1 {
			t.Fatal("recovery returned something other than the original creation", err)
		}
	}
	r.RequestID = "recover-altered-payload"
	c, _ = recoveryAttempt(t, f, f.db, r)
	altered := input
	altered.Destination = "Norway"
	got, err = c.Recover(ctx, r, recoveryKey, altered)
	requireRecoveryFailure(t, got, err, ErrCreationMismatch)
	r.RequestID = "recover-other-command"
	c, _ = recoveryAttempt(t, f, f.db, r)
	got, err = c.Recover(ctx, r, review.RequestKey, input)
	requireRecoveryFailure(t, got, err, ErrCreationUnconfirmed)
	if f.ids.Load() != 2 || recoverySnapshot(t, f) != before {
		t.Fatal("recovery generated IDs or changed existing records")
	}
}

func TestIntegrationCreationRecoveryScopeIsolation(t *testing.T) {
	f := persistent(t, "recover-scope")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const otherActor, otherOrg = "recovery-other-actor", "recovery-other-org"
	const otherMember, secondMember = "recovery-other-member", "recovery-second-member"
	// Provision three independently authorized alternate scopes before creating
	// the receipt. The same membership ID is valid in two distinct tenants.
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, end := context.WithTimeout(context.Background(), 3*time.Second)
		defer end()
		_ = tx.Rollback(cleanup)
	}()
	execAuthority(t, tx, "INSERT INTO softteros_access.actors VALUES($1)", otherActor)
	execAuthority(t, tx, "INSERT INTO softteros_access.actor_authority_fences VALUES($1,1)", otherActor)
	execAuthority(t, tx, "INSERT INTO softteros_access.organizations VALUES($1)", otherOrg)
	execAuthority(t, tx, "INSERT INTO softteros_access.organization_authority_fences VALUES($1,1)", otherOrg)
	for _, r := range []CreationRequest{
		{ActorID: otherActor, OrganizationID: f.r.OrganizationID, MembershipID: otherMember},
		{ActorID: f.r.ActorID, OrganizationID: f.r.OrganizationID, MembershipID: secondMember},
		{ActorID: f.r.ActorID, OrganizationID: otherOrg, MembershipID: f.r.MembershipID},
	} {
		execAuthority(t, tx, `INSERT INTO softteros_access.memberships VALUES
 ($1,$2,$3,true,false,'2000-01-01+00','9999-01-01+00')`, r.OrganizationID, r.MembershipID, r.ActorID)
		execAuthority(t, tx, "INSERT INTO softteros_access.membership_enquiry_capabilities VALUES($1,$2,'enquiries.create')", r.OrganizationID, r.MembershipID)
	}
	commitAuthority(t, tx)
	if _, err = f.creator.Create(ctx, f.r, recoveryKey, captureInput()); err != nil {
		t.Fatal("creation fixture", err)
	}
	for _, tc := range []struct {
		name, actor, org, member string
		want                     error
	}{
		{"actor-mismatch", otherActor, f.r.OrganizationID, f.r.MembershipID, authz.ErrUnauthorized},
		{"other-actor-membership", otherActor, f.r.OrganizationID, otherMember, ErrCreationUnconfirmed},
		{"same-actor-other-membership", f.r.ActorID, f.r.OrganizationID, secondMember, ErrCreationUnconfirmed},
		{"same-member-id-other-tenant", f.r.ActorID, otherOrg, f.r.MembershipID, ErrCreationUnconfirmed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := CreationRequest{ActorID: tc.actor, OrganizationID: tc.org, MembershipID: tc.member, RequestID: "recover-" + tc.name}
			c, _ := recoveryAttempt(t, f, f.db, r)
			got, err := c.Recover(ctx, r, recoveryKey, captureInput())
			requireRecoveryFailure(t, got, err, tc.want)
		})
	}
	r := f.r
	r.RequestID = "recovery-with-stale-attestation"
	c, _ := recoveryAttempt(t, f, f.db, r)
	// Still the right actor, but the adapter returns the original attempt's proof.
	c.authority.identity = identityFunc(func(context.Context, CreationIdentityRequest) (CreationAttestation, error) {
		return CreationAttestation{Actor: authz.Actor{ID: f.r.ActorID, Authenticated: true}, RequestID: f.r.RequestID}, nil
	})
	got, err := c.Recover(ctx, r, recoveryKey, captureInput())
	requireRecoveryFailure(t, got, err, authz.ErrUnauthorized)
	creationCounts(t, f, [3]int{1, 1, 1})
}

func TestIntegrationCreationRecoveryRejectsLostAuthority(t *testing.T) {
	for _, mode := range []string{"actor", "member", "capability", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			f := persistent(t, "recover-lost-"+mode)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := f.creator.Create(ctx, f.r, recoveryKey, captureInput()); err != nil {
				t.Fatal("creation fixture", err)
			}
			r := f.r
			r.RequestID = "recover-lost-" + mode
			c, identity := recoveryAttempt(t, f, f.db, r)
			tx := f.writer(t, f.admin, mode == "actor")
			switch mode {
			case "actor":
				identity.enabled.Store(false) // Synthetic identity under the exclusive actor fence.
			case "member":
				execAuthority(t, tx, "UPDATE softteros_access.memberships SET revoked=true WHERE organization_id=$1 AND membership_id=$2", r.OrganizationID, r.MembershipID)
			case "capability":
				revokeCapability(t, f.creationFixture, tx)
			case "expiry":
				execAuthority(t, tx, "UPDATE softteros_access.memberships SET valid_until=clock_timestamp() WHERE organization_id=$1 AND membership_id=$2", r.OrganizationID, r.MembershipID)
			}
			commitAuthority(t, tx)
			got, err := c.Recover(ctx, r, recoveryKey, captureInput())
			requireRecoveryFailure(t, got, err, authz.ErrUnauthorized)
			creationCounts(t, f, [3]int{1, 1, 1})
		})
	}
}

type recoveryAfterLookup struct {
	pg.Executor
	after func(context.Context) error
}

func (e recoveryAfterLookup) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	row := e.Executor.QueryRow(ctx, q, args...)
	if q != recoverCreationSQL {
		return row
	}
	return creationRow(func(dest ...any) error {
		if err := row.Scan(dest...); err != nil {
			return err
		}
		return e.after(ctx)
	})
}

func TestIntegrationCreationRecoveryExpiryAfterLookup(t *testing.T) {
	f := persistent(t, "recover-final-expiry")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := f.creator.Create(ctx, f.r, recoveryKey, captureInput()); err != nil {
		t.Fatal("creation fixture", err)
	}
	r := f.r
	r.RequestID = "recover-final-expiry"
	c, _ := recoveryAttempt(t, f, f.db, r)
	tx := f.writer(t, f.admin, false)
	execAuthority(t, tx, "UPDATE softteros_access.memberships SET valid_until=clock_timestamp()+interval '2 seconds' WHERE organization_id=$1 AND membership_id=$2", r.OrganizationID, r.MembershipID)
	commitAuthority(t, tx)
	paused, release, resume := pauseWriter(t)
	defer resume()
	c.authority.db = creationFixtureBoundary{db: f.db, role: f.role, wrap: func(e pg.Executor) pg.Executor {
		return recoveryAfterLookup{Executor: e, after: func(ctx context.Context) error { return pauseAt(ctx, paused, release) }}
	}}
	type result struct {
		ack RecoveredCreation
		err error
	}
	done := make(chan result, 1)
	go func() {
		ack, err := c.Recover(ctx, r, recoveryKey, captureInput())
		done <- result{ack, err}
	}()
	reachedWrite(t, paused) // The restricted role actually read a committed receipt.
	waitAuthorityExpiry(t, f.creationFixture)
	resume()
	select {
	case got := <-done:
		requireRecoveryFailure(t, got.ack, got.err, authz.ErrUnauthorized)
	case <-ctx.Done():
		t.Fatal("recovery did not finish after expiry")
	}
	creationCounts(t, f, [3]int{1, 1, 1})
}

func TestIntegrationCreationRecoveryConcurrentVisibility(t *testing.T) {
	for _, outcome := range []string{"commit", "rollback"} {
		t.Run(outcome, func(t *testing.T) {
			f := persistent(t, "recover-in-flight-"+outcome)
			peerDB, _, _ := database(t)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			paused, release, resume := pauseWriter(t)
			defer resume()
			f.creator.authority.db = creationFixtureBoundary{db: f.db, role: f.role, wrap: func(e pg.Executor) pg.Executor {
				return &persistentObserved{Executor: e, after: func(ctx context.Context, q string, _ []any) error {
					if q != creationIntegritySQL {
						return nil
					}
					if err := pauseAt(ctx, paused, release); err != nil {
						return err
					}
					if outcome == "rollback" {
						return errors.New("synthetic creation rollback before commit")
					}
					return nil
				}}
			}}
			first := startCreation(f.creator, f.r, recoveryKey, captureInput(), ctx)
			reachedWrite(t, paused) // All writes and deferred checks ran, but no commit yet.
			r := f.r
			r.RequestID = "recover-while-in-flight"
			c, _ := recoveryAttempt(t, f, peerDB, r)
			probe, stop := context.WithTimeout(ctx, 3*time.Second)
			got, err := c.Recover(probe, r, recoveryKey, captureInput())
			stop()
			requireRecoveryFailure(t, got, err, ErrCreationUnconfirmed)
			creationCounts(t, f, [3]int{})
			resume()
			prior := completedCreation(t, first)
			r.RequestID = "recover-after-" + outcome
			c, _ = recoveryAttempt(t, f, peerDB, r)
			got, err = c.Recover(ctx, r, recoveryKey, captureInput())
			if outcome == "rollback" {
				noCreated(t, prior, ErrStorage)
				requireRecoveryFailure(t, got, err, ErrCreationUnconfirmed)
				creationCounts(t, f, [3]int{})
			} else {
				if prior.err != nil {
					t.Fatal("original creation did not commit", prior.err)
				}
				want := RecoveredCreation{OrganizationID: f.r.OrganizationID, EnquiryID: prior.result.Enquiry.ID(),
					EventID: prior.result.EventID, Action: "enquiry.created", Version: 1, At: prior.result.Audit.At}
				if err != nil || got != want {
					t.Fatal("committed receipt did not become visible", err)
				}
				creationCounts(t, f, [3]int{1, 1, 1})
			}
			if f.ids.Load() != 2 {
				t.Fatal("recovery executed creation or generated IDs")
			}
		})
	}
}
