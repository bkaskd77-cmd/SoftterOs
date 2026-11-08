package postgres

import (
	"context"
	"crypto/rand"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries/application"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const reviewCreationKey = "capture-before-review"

type reviewFixture struct {
	*persistentFixture
	request ReviewRequest
	initial Created
	secret  [32]byte
	events  atomic.Int32
}

func newReviewFixture(t *testing.T, name string) *reviewFixture {
	t.Helper()
	f := &reviewFixture{persistentFixture: persistent(t, "review-"+name)}
	f.request = ReviewRequest{f.r.ActorID, f.r.OrganizationID, f.r.MembershipID, "start-" + name}
	f.initial = f.capture(t, reviewCreationKey)
	if _, err := rand.Read(f.secret[:]); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	return f
}

func (f *reviewFixture) capture(t *testing.T, key string) Created {
	t.Helper()
	got, err := f.creator.Create(context.Background(), f.r, key, captureInput())
	if err != nil {
		t.Fatal("create synthetic enquiry", err)
	}
	return got
}

func (f *reviewFixture) otherReviewer(t *testing.T) ReviewRequest {
	t.Helper()
	r := ReviewRequest{"other-" + f.r.ActorID, f.r.OrganizationID, "other-" + f.r.MembershipID, "other-" + f.request.RequestID}
	tx := f.writer(t, f.admin, false)
	execAuthority(t, tx, "SELECT set_config('softteros.actor_id',$1,true)", r.ActorID)
	execAuthority(t, tx, "INSERT INTO softteros_access.actors VALUES($1)", r.ActorID)
	execAuthority(t, tx, "INSERT INTO softteros_access.actor_authority_fences VALUES($1,7)", r.ActorID)
	execAuthority(t, tx, `INSERT INTO softteros_access.memberships
 VALUES($1,$2,$3,true,false,'2000-01-01+00','9999-01-01+00')`, r.OrganizationID, r.MembershipID, r.ActorID)
	commitAuthority(t, tx)
	return r
}

func insertReviewFixtureGrant(t *testing.T, tx pgx.Tx, request ReviewRequest, id, enquiryID string, capability authz.Capability) {
	t.Helper()
	execAuthority(t, tx, `INSERT INTO softteros_access.enquiry_transition_grants
 VALUES($1,$2,$3,$4,$5,$6,true,false,'2000-01-01+00','9999-01-01+00')`,
		request.OrganizationID, id, request.ActorID, request.MembershipID, enquiryID, capability)
}

func (f *reviewFixture) grant(t *testing.T, request ReviewRequest, id, enquiryID string) {
	t.Helper()
	tx := f.writer(t, f.admin, false)
	execAuthority(t, tx, `INSERT INTO softteros_access.membership_enquiry_capabilities
 VALUES($1,$2,'enquiries.review') ON CONFLICT DO NOTHING`, request.OrganizationID, request.MembershipID)
	insertReviewFixtureGrant(t, tx, request, id, enquiryID, authz.CapabilityReviewEnquiry)
	commitAuthority(t, tx)
}

func (f *reviewFixture) starter(t *testing.T, db *pg.DB, request ReviewRequest, wrap func(pg.Executor) pg.Executor) *ReviewStarter {
	t.Helper()
	identity := reviewIdentityFunc(func(ctx context.Context, r ReviewIdentityRequest) (ReviewAttestation, error) {
		if err := ctx.Err(); err != nil {
			return ReviewAttestation{}, err
		}
		if r != (ReviewIdentityRequest{request.ActorID, request.RequestID}) {
			return ReviewAttestation{}, errors.New("fixture actor/request binding mismatch")
		}
		return ReviewAttestation{Actor: authz.Actor{ID: r.ActorID, Authenticated: true, Human: true}, RequestID: r.RequestID}, nil
	})
	starter, err := NewReviewStarter(db, identity, f.secret[:], func() (string, error) {
		return f.initial.Enquiry.ID() + "-review-" + strconv.Itoa(int(f.events.Add(1))), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	boundary := creationFixtureBoundary{db: db, role: f.role, wrap: wrap}
	starter.db = boundary
	if wrap != nil {
		// A test-only budget for observing real waits and database time.
		starter.db = readBoundaryFunc(func(ctx context.Context, scope pg.Scope, fn func(context.Context, pg.Executor) error) error {
			return boundary.WithTx(ctx, scope, func(ctx context.Context, tx pg.Executor) error {
				if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout='5s'"); err != nil {
					return err
				}
				return fn(ctx, tx)
			})
		})
	}
	return starter
}

func noStartedReview(t *testing.T, got StartedReview, err, want error) {
	t.Helper()
	if got != (StartedReview{}) || !errors.Is(err, want) {
		t.Fatalf("unexpected review result, error %v, want %v and an empty acknowledgement", err, want)
	}
}

func (f *reviewFixture) assertCommitted(t *testing.T, request ReviewRequest, grantID, requestKey string, got StartedReview) {
	t.Helper()
	id := f.initial.Enquiry.ID()
	if got.OrganizationID != request.OrganizationID || got.EnquiryID != id || !identifier(got.EventID) ||
		got.AssigneeMembershipID != request.MembershipID || got.State != enquiries.StateUnderReview ||
		got.Version != 2 || got.At.Before(f.initial.Audit.At) {
		t.Fatal("wrong committed acknowledgement")
	}
	proof := reviewProof(t, request.OrganizationID, request.ActorID, request.MembershipID, id, grantID,
		authz.CapabilityReviewEnquiry, created)
	mac, err := reviewFingerprint(f.secret, proof, id, requestKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var linked bool
	err = f.admin.QueryRow(ctx, `SELECT EXISTS(
 SELECT 1 FROM softteros_enquiries.enquiry_events v
 JOIN softteros_enquiries.enquiry_command_receipts r USING (organization_id,membership_id,request_key)
 JOIN softteros_access.actor_authority_fences a ON a.actor_id=v.actor_id
 JOIN softteros_access.organization_authority_fences o USING (organization_id)
 WHERE v.organization_id=$1 AND v.enquiry_id=$2 AND v.event_id=$3 AND v.actor_id=$4 AND v.membership_id=$5
  AND v.grant_id=$6 AND v.request_key=$7 AND v.at=$8 AND v.active_organization_id=$1
  AND v.action='enquiry.review_started' AND v.capability='enquiries.review' AND v.outcome='success'
  AND v.actor_authority_revision=a.revision AND v.organization_authority_revision=o.revision
  AND v.previous_state='New' AND v.new_state='Under review' AND v.previous_version=1 AND v.resulting_version=2
  AND v.previous_assignee_membership_id IS NULL AND v.assignee_membership_id=$5
  AND r.actor_id=$4 AND r.enquiry_id=$2 AND r.event_id=$3 AND r.command=v.action AND r.expected_version=1
  AND r.resulting_version=2 AND r.completed AND r.completed_at>=v.at
  AND r.fingerprint_version=1 AND r.fingerprint=$9
 )`, request.OrganizationID, id, got.EventID, request.ActorID, request.MembershipID, grantID, requestKey, got.At, mac[:]).Scan(&linked)
	if err != nil || !linked {
		t.Fatal("review event or receipt attribution differs", err)
	}
	err = (creationFixtureBoundary{db: f.db, role: f.role}).WithTx(ctx,
		pg.Scope{ActorID: request.ActorID, OrganizationID: request.OrganizationID}, func(ctx context.Context, tx pg.Executor) error {
			loaded, err := Load(ctx, tx, request.OrganizationID, id)
			if err != nil {
				return err
			}
			want := f.initial.Enquiry.Snapshot()
			want.State, want.Version, want.AssigneeMembershipID, want.LastChangedAt = enquiries.StateUnderReview, 2, request.MembershipID, got.At
			if loaded.Enquiry.Snapshot() != want || len(loaded.Transitions) != 1 {
				return errors.New("committed review did not preserve the enquiry and its history")
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationStartReviewThenAssignedRead(t *testing.T) {
	f := newReviewFixture(t, "read")
	id := f.initial.Enquiry.ID()
	reviewer := f.otherReviewer(t)
	f.grant(t, reviewer, "reviewer-grant", id)
	starter := f.starter(t, f.db, reviewer, nil)
	got, err := starter.StartReview(context.Background(), reviewer, id, 1, "review-key")
	if err != nil {
		t.Fatal(err)
	}
	f.assertCommitted(t, reviewer, "reviewer-grant", "review-key", got)
	creationCounts(t, f.persistentFixture, [3]int{1, 2, 2})

	readRequest := application.ReadRequest{ActorID: reviewer.ActorID, OrganizationID: reviewer.OrganizationID,
		MembershipID: reviewer.MembershipID, RequestID: "read-after-review"}
	reader := (&assignedReadFixture{persistentFixture: f.persistentFixture}).reader(t, readRequest, nil)
	view, err := reader.GetEnquiry(context.Background(), readRequest, id)
	requireUnavailableRead(t, view, err)
	tx := f.writer(t, f.admin, false)
	execAuthority(t, tx, "INSERT INTO softteros_access.membership_enquiry_capabilities VALUES($1,$2,'enquiries.read')",
		reviewer.OrganizationID, reviewer.MembershipID)
	commitAuthority(t, tx)
	view, err = reader.GetEnquiry(context.Background(), readRequest, id)
	input := f.initial.Enquiry.Input()
	want := application.EnquiryDetails{EnquiryID: id, State: enquiries.StateUnderReview, Version: 2,
		Destination: input.Destination, TravellerCount: input.TravellerCount, TravelStart: input.TravelStart, TravelEnd: input.TravelEnd}
	if err != nil || view != want {
		t.Fatal("separately entitled assignee did not get the narrow version-2 view", err)
	}
}

func TestIntegrationStartReviewGrantResolution(t *testing.T) {
	f := newReviewFixture(t, "grant")
	id := f.initial.Enquiry.ID()
	otherID := f.capture(t, "other-enquiry").Enquiry.ID()
	other := f.request
	other.MembershipID = "second-membership-for-actor"
	starter := f.starter(t, f.db, f.request, nil)
	tx := f.writer(t, f.admin, false)
	execAuthority(t, tx, `INSERT INTO softteros_access.memberships
 VALUES($1,$2,$3,true,false,'2000-01-01+00','9999-01-01+00')`, other.OrganizationID, other.MembershipID, other.ActorID)
	execAuthority(t, tx, "INSERT INTO softteros_access.membership_enquiry_capabilities VALUES($1,$2,'enquiries.review')",
		f.request.OrganizationID, f.request.MembershipID)
	commitAuthority(t, tx)
	expectDenied := func() {
		t.Helper()
		before := recoverySnapshot(t, f.persistentFixture)
		got, err := starter.StartReview(context.Background(), f.request, id, 1, "review-key")
		noStartedReview(t, got, err, authz.ErrTransitionUnauthorized)
		if f.events.Load() != 0 || recoverySnapshot(t, f.persistentFixture) != before {
			t.Fatal("invalid grant produced business side effects")
		}
	}
	expectDenied() // No grant exists.
	tx = f.writer(t, f.admin, false)
	for _, grant := range []string{"expired", "revoked", "inactive", "future"} {
		insertReviewFixtureGrant(t, tx, f.request, grant, id, authz.CapabilityReviewEnquiry)
	}
	execAuthority(t, tx, `UPDATE softteros_access.enquiry_transition_grants SET
 active=grant_id<>'inactive',revoked=grant_id='revoked',
 valid_from=CASE WHEN grant_id='future' THEN '9998-01-01+00'::timestamptz ELSE valid_from END,
 valid_until=CASE WHEN grant_id='expired' THEN '2001-01-01+00'::timestamptz ELSE valid_until END
 WHERE organization_id=$1`, f.request.OrganizationID)
	insertReviewFixtureGrant(t, tx, f.request, "other-capability", id, authz.CapabilityQualifyEnquiry)
	insertReviewFixtureGrant(t, tx, f.request, "other-target", otherID, authz.CapabilityReviewEnquiry)
	insertReviewFixtureGrant(t, tx, other, "other-membership", id, authz.CapabilityReviewEnquiry)
	commitAuthority(t, tx)
	expectDenied()

	f.grant(t, f.request, "first-eligible", id)
	f.grant(t, f.request, "second-eligible", id)
	expectDenied()
	tx = f.writer(t, f.admin, false)
	execAuthority(t, tx, "UPDATE softteros_access.enquiry_transition_grants SET revoked=true WHERE organization_id=$1 AND grant_id='first-eligible'",
		f.request.OrganizationID)
	commitAuthority(t, tx)
	got, err := starter.StartReview(context.Background(), f.request, id, 1, "review-key")
	if err != nil {
		t.Fatal("exactly one eligible grant among ineligible rows was denied", err)
	}
	f.assertCommitted(t, f.request, "second-eligible", "review-key", got)
	creationCounts(t, f.persistentFixture, [3]int{2, 3, 3})
}

func TestIntegrationStartReviewDenials(t *testing.T) {
	for _, name := range []string{"nonhuman", "wrong-request", "wrong-actor", "wrong-membership", "inactive", "revoked", "expired", "other-capabilities", "admin-without-review"} {
		t.Run(name, func(t *testing.T) {
			f := newReviewFixture(t, name)
			id := f.initial.Enquiry.ID()
			f.grant(t, f.request, "main-grant", id)
			request := f.request
			if name == "wrong-membership" {
				other := f.otherReviewer(t)
				f.grant(t, other, "other-grant", id)
				request.MembershipID = other.MembershipID
			}
			starter := f.starter(t, f.db, request, nil)
			switch name {
			case "nonhuman", "wrong-request", "wrong-actor":
				starter.identity = reviewIdentityFunc(func(_ context.Context, r ReviewIdentityRequest) (ReviewAttestation, error) {
					a := ReviewAttestation{Actor: authz.Actor{ID: r.ActorID, Authenticated: true, Human: true}, RequestID: r.RequestID}
					switch name {
					case "nonhuman":
						a.Actor.Human = false
					case "wrong-request":
						a.RequestID = "different-attempt"
					case "wrong-actor":
						a.Actor.ID = "different-actor"
					}
					return a, nil
				})
			case "inactive", "revoked", "expired":
				tx := f.writer(t, f.admin, false)
				set := map[string]string{"inactive": "active=false", "revoked": "revoked=true", "expired": "valid_until=clock_timestamp()"}[name]
				execAuthority(t, tx, "UPDATE softteros_access.memberships SET "+set+" WHERE organization_id=$1 AND membership_id=$2",
					f.request.OrganizationID, f.request.MembershipID)
				commitAuthority(t, tx)
			case "other-capabilities", "admin-without-review":
				tx := f.writer(t, f.admin, false)
				execAuthority(t, tx, `DELETE FROM softteros_access.membership_enquiry_capabilities
 WHERE organization_id=$1 AND membership_id=$2 AND capability='enquiries.review'`, f.request.OrganizationID, f.request.MembershipID)
				execAuthority(t, tx, `INSERT INTO softteros_access.membership_enquiry_capabilities
 VALUES($1,$2,'enquiries.read'),($1,$2,'enquiries.qualify')`, f.request.OrganizationID, f.request.MembershipID)
				commitAuthority(t, tx)
				if name == "admin-without-review" {
					starter.db = f.db
				}
			}
			before := recoverySnapshot(t, f.persistentFixture)
			got, err := starter.StartReview(context.Background(), request, id, 1, "review-key")
			noStartedReview(t, got, err, authz.ErrTransitionUnauthorized)
			if f.events.Load() != 0 || recoverySnapshot(t, f.persistentFixture) != before {
				t.Fatal("review denial changed records or generated an event ID")
			}
		})
	}
}

func TestIntegrationStartReviewTenantAndDuplicateKeys(t *testing.T) {
	f, foreign := newReviewFixture(t, "keys"), newReviewFixture(t, "foreign")
	id := f.initial.Enquiry.ID()
	f.grant(t, f.request, "main-grant", id)
	foreign.grant(t, foreign.request, "foreign-grant", foreign.initial.Enquiry.ID())
	starter := f.starter(t, f.db, f.request, nil)
	before, foreignBefore := recoverySnapshot(t, f.persistentFixture), recoverySnapshot(t, foreign.persistentFixture)
	for _, tc := range []struct {
		id, key string
		version uint64
		err     error
	}{
		{foreign.initial.Enquiry.ID(), "review-key", 1, authz.ErrTransitionUnauthorized},
		{"missing-enquiry", "review-key", 1, authz.ErrTransitionUnauthorized},
		{id, "review-key", 2, enquiries.ErrVersionConflict},
		{id, reviewCreationKey, 1, ErrDuplicateReview},
	} {
		got, err := starter.StartReview(context.Background(), f.request, tc.id, tc.version, tc.key)
		noStartedReview(t, got, err, tc.err)
	}
	if f.events.Load() != 0 || recoverySnapshot(t, f.persistentFixture) != before ||
		recoverySnapshot(t, foreign.persistentFixture) != foreignBefore {
		t.Fatal("denied review changed local or foreign records")
	}

	got, err := starter.StartReview(context.Background(), f.request, id, 1, "review-key")
	if err != nil {
		t.Fatal(err)
	}
	f.assertCommitted(t, f.request, "main-grant", "review-key", got)
	after := recoverySnapshot(t, f.persistentFixture)
	for key, want := range map[string]error{"review-key": ErrDuplicateReview, "stale-version-key": enquiries.ErrVersionConflict} {
		got, err := starter.StartReview(context.Background(), f.request, id, 1, key)
		noStartedReview(t, got, err, want)
	}
	if recoverySnapshot(t, f.persistentFixture) != after || f.events.Load() != 1 {
		t.Fatal("duplicate or stale review changed committed records")
	}
}

type reviewCompletion struct {
	result StartedReview
	err    error
}

func startReviewAttempt(t *testing.T, ctx context.Context, r *ReviewStarter, request ReviewRequest, id, key string) <-chan reviewCompletion {
	t.Helper()
	return startAssignedReadWork(t, func() reviewCompletion {
		got, err := r.StartReview(ctx, request, id, 1, key)
		return reviewCompletion{got, err}
	})
}

func completedReview(t *testing.T, done <-chan reviewCompletion) reviewCompletion {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(6 * time.Second):
		t.Fatal("review did not finish")
		return reviewCompletion{}
	}
}

func TestIntegrationStartReviewCompetingReviewers(t *testing.T) {
	f := newReviewFixture(t, "compete")
	id, key := f.initial.Enquiry.ID(), "claim-key"
	secondRequest := f.otherReviewer(t)
	f.grant(t, f.request, "first-reviewer", id)
	f.grant(t, secondRequest, "second-reviewer", id)
	peer, _, _ := database(t)
	firstReserved, firstRelease, firstProceed := pauseWriter(t)
	secondReserved, secondRelease, secondProceed := pauseWriter(t)
	firstReady, firstCommit, firstFinish := pauseWriter(t)
	firstPID, secondPID := make(chan uint32, 1), make(chan uint32, 1)

	reservationBarrier := func(ctx context.Context, tx pg.Executor, request ReviewRequest, reached, release chan struct{}, pid chan uint32) error {
		var pending bool
		var backend uint32
		if err := tx.QueryRow(ctx, `SELECT pg_backend_pid(),EXISTS (
 SELECT 1 FROM softteros_enquiries.enquiry_command_receipts
 WHERE organization_id=$1 AND membership_id=$2 AND request_key=$3 AND actor_id=$4
 AND enquiry_id=$5 AND command='enquiry.review_started' AND NOT completed
 AND event_id IS NULL AND resulting_version IS NULL AND completed_at IS NULL)`,
			request.OrganizationID, request.MembershipID, key, request.ActorID, id).Scan(&backend, &pending); err != nil {
			return err
		}
		if !pending {
			return errors.New("claim reached row-lock boundary without its pending receipt")
		}
		// Independently exercise compatibility with FK-style key-share locks.
		// The actual receipt has no direct FK to the enquiry. Both attempts
		// hold this test lock before either attempts the production write lock.
		var locked string
		if err := tx.QueryRow(ctx, `SELECT enquiry_id::text FROM softteros_enquiries.enquiries
 WHERE organization_id=$1 AND enquiry_id=$2 FOR KEY SHARE`, request.OrganizationID, id).Scan(&locked); err != nil {
			return err
		}
		if locked != id {
			return errors.New("test locked a different enquiry")
		}
		pid <- backend
		return pauseAt(ctx, reached, release)
	}
	first := f.starter(t, f.db, f.request, func(e pg.Executor) pg.Executor {
		return &persistentObserved{Executor: e, after: func(ctx context.Context, q string, _ []any) error {
			switch q {
			case reserveReviewSQL:
				return reservationBarrier(ctx, e, f.request, firstReserved, firstRelease, firstPID)
			case reviewIntegritySQL:
				return pauseAt(ctx, firstReady, firstCommit)
			}
			return nil
		}}
	})
	second := f.starter(t, peer, secondRequest, func(e pg.Executor) pg.Executor {
		return &persistentObserved{Executor: e, after: func(ctx context.Context, q string, _ []any) error {
			if q == reserveReviewSQL {
				return reservationBarrier(ctx, e, secondRequest, secondReserved, secondRelease, secondPID)
			}
			return nil
		}}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	one := startReviewAttempt(t, ctx, first, f.request, id, key)
	reachedWrite(t, firstReserved)
	two := startReviewAttempt(t, ctx, second, secondRequest, id, key)
	reachedWrite(t, secondReserved)
	creationCounts(t, f.persistentFixture, [3]int{1, 1, 1})
	firstProceed()
	// The second key-share holder is still paused. An unnecessarily strong
	// FOR UPDATE would block the first claim here.
	reachedWrite(t, firstReady)
	secondProceed()
	waitAssignedBlocked(t, f.admin, authorityPID(t, secondPID), authorityPID(t, firstPID))
	firstFinish()
	winner, loser := completedReview(t, one), completedReview(t, two)
	if winner.err != nil {
		t.Fatal("first claimant failed", winner.err)
	}
	noStartedReview(t, loser.result, loser.err, enquiries.ErrVersionConflict)
	f.assertCommitted(t, f.request, "first-reviewer", key, winner.result)
	creationCounts(t, f.persistentFixture, [3]int{1, 2, 2})
	if f.events.Load() != 1 {
		t.Fatal("losing claim generated an event ID")
	}
}

func TestIntegrationStartReviewConcurrentDuplicate(t *testing.T) {
	f := newReviewFixture(t, "duplicate")
	id, key := f.initial.Enquiry.ID(), "review-key"
	f.grant(t, f.request, "main-grant", id)
	peer, _, _ := database(t)
	reserved, release, resume := pauseWriter(t)
	firstPID, secondPID := make(chan uint32, 1), make(chan uint32, 1)
	first := f.starter(t, f.db, f.request, func(e pg.Executor) pg.Executor {
		return &persistentObserved{Executor: e, after: func(ctx context.Context, q string, _ []any) error {
			if q != reserveReviewSQL {
				return nil
			}
			if err := assignedReadPID(reserveReviewSQL, firstPID)(ctx, q, e); err != nil {
				return err
			}
			return pauseAt(ctx, reserved, release)
		}}
	})
	secondRequest := f.request
	secondRequest.RequestID = "independent-duplicate-attempt"
	second := f.starter(t, peer, secondRequest, func(e pg.Executor) pg.Executor {
		return &persistentObserved{Executor: e, before: func(ctx context.Context, q string, _ []any) error {
			return assignedReadPID(reserveReviewSQL, secondPID)(ctx, q, e)
		}}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	one := startReviewAttempt(t, ctx, first, f.request, id, key)
	reachedWrite(t, reserved)
	two := startReviewAttempt(t, ctx, second, secondRequest, id, key)
	waitAssignedBlocked(t, f.admin, authorityPID(t, secondPID), authorityPID(t, firstPID))
	resume()
	winner, duplicate := completedReview(t, one), completedReview(t, two)
	if winner.err != nil {
		t.Fatal(winner.err)
	}
	noStartedReview(t, duplicate.result, duplicate.err, ErrDuplicateReview)
	f.assertCommitted(t, f.request, "main-grant", key, winner.result)
	creationCounts(t, f.persistentFixture, [3]int{1, 2, 2})
}

func TestIntegrationStartReviewRollbackAndCancellation(t *testing.T) {
	for _, stage := range []string{"event-failure", "deferred-integrity", "cancel-after-update"} {
		t.Run(stage, func(t *testing.T) {
			f := newReviewFixture(t, stage)
			id, key := f.initial.Enquiry.ID(), "review-key"
			f.grant(t, f.request, "main-grant", id)
			before := recoverySnapshot(t, f.persistentFixture)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var beforePID, afterPID uint32
			var state string
			reachedIntegrity := false
			starter := f.starter(t, f.db, f.request, func(e pg.Executor) pg.Executor {
				return &persistentObserved{Executor: e, before: func(ctx context.Context, q string, args []any) error {
					switch q {
					case reserveReviewSQL:
						return e.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&beforePID)
					case insertReviewEventSQL:
						switch stage {
						case "event-failure":
							_, err := e.Exec(ctx, "SELECT 1/0")
							var server *pgconn.PgError
							if errors.As(err, &server) {
								state = server.Code
							}
							return err
						case "deferred-integrity":
							// Structurally valid event with a timestamp different
							// from the enquiry's last change. The deferred history
							// check rejects the linked row/event/receipt together.
							last := len(args) - 1
							args[last] = args[last].(time.Time).Add(time.Microsecond)
						}
					case reviewIntegritySQL:
						reachedIntegrity = true
					}
					return nil
				}, after: func(_ context.Context, q string, _ []any) error {
					if q == updateReviewEnquirySQL && stage == "cancel-after-update" {
						cancel()
					}
					return nil
				}}
			})
			got, err := starter.StartReview(ctx, f.request, id, 1, key)
			if stage == "cancel-after-update" {
				noStartedReview(t, got, err, context.Canceled)
			} else {
				noStartedReview(t, got, err, ErrStorage)
				if err.Error() != ErrStorage.Error() {
					t.Fatal("storage failure exposed diagnostics")
				}
			}
			if errors.Is(err, pg.ErrCleanup) || recoverySnapshot(t, f.persistentFixture) != before ||
				(stage == "event-failure" && state != "22012") || (stage == "deferred-integrity" && !reachedIntegrity) {
				t.Fatal("expected a clean rollback of all review writes", err)
			}
			err = f.db.WithTx(context.Background(), pg.Scope{ActorID: f.request.ActorID, OrganizationID: f.request.OrganizationID},
				func(ctx context.Context, e pg.Executor) error {
					return e.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&afterPID)
				})
			if err != nil || beforePID == 0 || beforePID != afterPID {
				t.Fatal("healthy backend was not cleaned and reused", err)
			}
			starter = f.starter(t, f.db, f.request, nil)
			if _, err = starter.StartReview(context.Background(), f.request, id, 1, key); err != nil {
				t.Fatal("known rollback did not release the reservation", err)
			}
			creationCounts(t, f.persistentFixture, [3]int{1, 2, 2})
		})
	}
}

func waitReviewClock(t *testing.T, conn *pgx.Conn, at time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var reached bool
		if err := conn.QueryRow(ctx, "SELECT clock_timestamp()>=$1", at).Scan(&reached); err != nil {
			t.Fatal("read expiry barrier", err)
		}
		if reached {
			return
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("database did not reach eligibility boundary")
		}
	}
}

func TestIntegrationStartReviewRechecksEligibility(t *testing.T) {
	for _, change := range []string{"grant-expiry-at-lock", "new-overlap-at-lock", "grant-expiry-after-integrity", "membership-expiry-after-integrity"} {
		t.Run(change, func(t *testing.T) {
			f := newReviewFixture(t, change)
			id := f.initial.Enquiry.ID()
			f.grant(t, f.request, "main-grant", id)
			before := recoverySnapshot(t, f.persistentFixture)
			atFinalGate := change == "grant-expiry-after-integrity" || change == "membership-expiry-after-integrity"
			var holderConn *pgx.Conn
			var holder pgx.Tx
			if !atFinalGate {
				_, holderConn, _ = database(t)
				holder = beginAssignedFixtureTx(t, holderConn)
				execAuthority(t, holder, "SELECT enquiry_id FROM softteros_enquiries.enquiries WHERE organization_id=$1 AND enquiry_id=$2 FOR NO KEY UPDATE",
					f.request.OrganizationID, id)
			}
			writer := f.writer(t, f.admin, false)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			var cutover time.Time
			if err := writer.QueryRow(ctx, "SELECT clock_timestamp()+interval '2 seconds'").Scan(&cutover); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "grant-expiry-at-lock", "grant-expiry-after-integrity":
				execAuthority(t, writer, "UPDATE softteros_access.enquiry_transition_grants SET valid_until=$2 WHERE organization_id=$1 AND grant_id='main-grant'",
					f.request.OrganizationID, cutover)
			case "new-overlap-at-lock":
				insertReviewFixtureGrant(t, writer, f.request, "future-grant", id, authz.CapabilityReviewEnquiry)
				execAuthority(t, writer, "UPDATE softteros_access.enquiry_transition_grants SET valid_from=$2 WHERE organization_id=$1 AND grant_id='future-grant'",
					f.request.OrganizationID, cutover)
			case "membership-expiry-after-integrity":
				execAuthority(t, writer, "UPDATE softteros_access.memberships SET valid_until=$3 WHERE organization_id=$1 AND membership_id=$2",
					f.request.OrganizationID, f.request.MembershipID, cutover)
			}
			commitAuthority(t, writer)
			checked, release, resume := pauseWriter(t)
			pid := make(chan uint32, 1)
			starter := f.starter(t, f.db, f.request, func(e pg.Executor) pg.Executor {
				return &persistentObserved{
					Executor: observedAssignedRead{Executor: e, before: assignedReadPID(lockReviewEnquirySQL, pid)},
					after: func(ctx context.Context, q string, _ []any) error {
						if q == reviewIntegritySQL && atFinalGate {
							return pauseAt(ctx, checked, release)
						}
						return nil
					},
				}
			})
			done := startReviewAttempt(t, ctx, starter, f.request, id, "review-key")
			if atFinalGate {
				reachedWrite(t, checked)
				if recoverySnapshot(t, f.persistentFixture) != before {
					t.Fatal("uncommitted review became visible")
				}
			} else {
				waitAssignedBlocked(t, f.admin, authorityPID(t, pid), holderConn.PgConn().PID())
			}
			waitReviewClock(t, f.admin, cutover)
			if atFinalGate {
				resume()
			} else {
				commitAuthority(t, holder)
			}
			failed := completedReview(t, done)
			noStartedReview(t, failed.result, failed.err, authz.ErrTransitionUnauthorized)
			if recoverySnapshot(t, f.persistentFixture) != before || (!atFinalGate && f.events.Load() != 0) {
				t.Fatal("stale review authority left business changes")
			}
		})
	}
}

func TestIntegrationStartReviewRevocationOrdering(t *testing.T) {
	t.Run("revocation first", func(t *testing.T) {
		f := newReviewFixture(t, "revoked-first")
		id := f.initial.Enquiry.ID()
		f.grant(t, f.request, "main-grant", id)
		_, observer, _ := database(t)
		before := recoverySnapshot(t, f.persistentFixture)
		writer := f.writer(t, f.admin, false)
		execAuthority(t, writer, "UPDATE softteros_access.enquiry_transition_grants SET revoked=true WHERE organization_id=$1 AND grant_id='main-grant'",
			f.request.OrganizationID)
		pid := make(chan uint32, 1)
		starter := f.starter(t, f.db, f.request, observeAssignedRead(assignedReadPID(creationFenceSQL, pid), nil))
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		done := startReviewAttempt(t, ctx, starter, f.request, id, "review-key")
		waitAssignedBlocked(t, observer, authorityPID(t, pid), f.admin.PgConn().PID())
		commitAuthority(t, writer)
		got := completedReview(t, done)
		noStartedReview(t, got.result, got.err, authz.ErrTransitionUnauthorized)
		if recoverySnapshot(t, f.persistentFixture) != before || f.events.Load() != 0 {
			t.Fatal("revocation ordered first did not stop review")
		}
	})
	t.Run("review first", func(t *testing.T) {
		f := newReviewFixture(t, "review-first")
		id := f.initial.Enquiry.ID()
		f.grant(t, f.request, "main-grant", id)
		writer := assignedReadPeer(t, &assignedReadFixture{persistentFixture: f.persistentFixture})
		checked, release, resume := pauseWriter(t)
		pid := make(chan uint32, 1)
		starter := f.starter(t, f.db, f.request, func(e pg.Executor) pg.Executor {
			return &persistentObserved{Executor: e, after: func(ctx context.Context, q string, _ []any) error {
				if q != reviewIntegritySQL {
					return nil
				}
				if err := assignedReadPID(reviewIntegritySQL, pid)(ctx, q, e); err != nil {
					return err
				}
				return pauseAt(ctx, checked, release)
			}}
		})
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		done := startReviewAttempt(t, ctx, starter, f.request, id, "review-key")
		reachedWrite(t, checked)
		writerDone := startAssignedReadWork(t, func() error {
			return revokeAfterFences(ctx, writer, f.persistentFixture, authz.CapabilityReviewEnquiry)
		})
		waitAssignedBlocked(t, f.admin, writer.PgConn().PID(), authorityPID(t, pid))
		resume()
		if got := completedReview(t, done); got.err != nil || got.result.AssigneeMembershipID != f.request.MembershipID {
			t.Fatal("review ordered first did not complete", got.err)
		}
		if err := authorityResult(t, writerDone); err != nil {
			t.Fatal("revocation did not complete after review", err)
		}
		starter = f.starter(t, f.db, f.request, nil)
		got, err := starter.StartReview(ctx, f.request, id, 1, "after-revocation")
		noStartedReview(t, got, err, authz.ErrTransitionUnauthorized)
		creationCounts(t, f.persistentFixture, [3]int{1, 2, 2})
	})
}

func TestIntegrationStartReviewCompletionOutcomes(t *testing.T) {
	for _, outcome := range []error{pg.ErrCommitRejected, pg.ErrCommitUnknown} {
		t.Run(outcome.Error(), func(t *testing.T) {
			f := newReviewFixture(t, "completion-"+strconv.FormatBool(outcome == pg.ErrCommitUnknown))
			id := f.initial.Enquiry.ID()
			f.grant(t, f.request, "main-grant", id)
			before := recoverySnapshot(t, f.persistentFixture)
			starter := f.starter(t, f.db, f.request, nil)
			boundary := starter.db
			simulatedRollback := errors.New("simulate commit rejection by rolling back")
			calls := 0
			starter.db = readBoundaryFunc(func(ctx context.Context, s pg.Scope, fn func(context.Context, pg.Executor) error) error {
				calls++
				err := boundary.WithTx(ctx, s, func(ctx context.Context, tx pg.Executor) error {
					if err := fn(ctx, tx); err != nil {
						return err
					}
					if outcome == pg.ErrCommitRejected {
						return simulatedRollback
					}
					return nil
				})
				// This tests the command's result gating and lack of retries.
				// The transaction infrastructure has separate wire-level tests.
				if (outcome == pg.ErrCommitUnknown && err == nil) || (outcome == pg.ErrCommitRejected && err == simulatedRollback) {
					return outcome
				}
				return err
			})
			got, err := starter.StartReview(context.Background(), f.request, id, 1, "review-key")
			noStartedReview(t, got, err, outcome)
			if calls != 1 || f.events.Load() != 1 {
				t.Fatal("completion error caused re-execution")
			}
			if outcome == pg.ErrCommitUnknown {
				creationCounts(t, f.persistentFixture, [3]int{1, 2, 2})
			} else if recoverySnapshot(t, f.persistentFixture) != before {
				t.Fatal("simulated rejection did not roll back")
			}
		})
	}
}
