package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const recoveredReviewKey = "original-review-key"

// Reuse the coordinated synthetic identity fixture, bound to this fresh attempt.
func reviewRecoverer(t *testing.T, f *reviewFixture, db *pg.DB, request ReviewRequest, wrap func(pg.Executor) pg.Executor) (*ReviewStarter, *fixtureIdentity) {
	t.Helper()
	if request.RequestID == f.request.RequestID || request.RequestID == recoveredReviewKey {
		t.Fatal("recovery needs a fresh attestation request")
	}
	identity := &fixtureIdentity{actor: request.ActorID, request: request.RequestID}
	identity.enabled.Store(true)
	r, err := NewReviewStarter(db, reviewIdentityFunc(func(ctx context.Context, q ReviewIdentityRequest) (ReviewAttestation, error) {
		value, err := identity.CurrentCreation(ctx, CreationIdentityRequest{ActorID: q.ActorID, RequestID: q.RequestID})
		return ReviewAttestation{Actor: value.Actor, RequestID: value.RequestID}, err
	}), f.secret[:], func() (string, error) { t.Fatal("recovery generated an ID"); return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	r.db = creationFixtureBoundary{db: db, role: f.role, wrap: func(e pg.Executor) pg.Executor {
		if wrap != nil {
			e = wrap(e)
		}
		return reviewRecoveryReadOnly{e}
	}}
	return r, identity
}

type reviewRecoveryReadOnly struct{ pg.Executor }

func (reviewRecoveryReadOnly) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("recovery attempted a write")
}

func completedReviewFixture(t *testing.T, name string, secondActor bool) (*reviewFixture, ReviewRequest, StartedReview) {
	t.Helper()
	f := newReviewFixture(t, "recover-"+name)
	request := f.request
	if secondActor {
		request = f.otherReviewer(t)
	}
	f.grant(t, request, "original-grant", f.initial.Enquiry.ID())
	r := f.starter(t, f.db, request, nil)
	got, err := r.StartReview(context.Background(), request, f.initial.Enquiry.ID(), 1, recoveredReviewKey)
	if err != nil {
		t.Fatal("review fixture", err)
	}
	f.assertCommitted(t, request, "original-grant", recoveredReviewKey, got)
	request.RequestID = "recover-" + name
	return f, request, got
}

func reviewRecoveryWriter(t *testing.T, f *reviewFixture, conn *pgx.Conn, request ReviewRequest, actor bool) pgx.Tx {
	t.Helper()
	fixture := *f.creationFixture
	fixture.r = CreationRequest{request.ActorID, request.OrganizationID, request.MembershipID, request.RequestID}
	return fixture.writer(t, conn, actor)
}

func originalReviewCreation(t *testing.T, f *reviewFixture) string {
	t.Helper()
	ctx, end := context.WithTimeout(context.Background(), 3*time.Second)
	defer end()
	var snapshot string
	err := f.admin.QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT to_jsonb(v) FROM softteros_enquiries.enquiry_events v WHERE organization_id=$1 AND event_id=$2),
 (SELECT to_jsonb(r) FROM softteros_enquiries.enquiry_command_receipts r WHERE organization_id=$1 AND event_id=$2))::text`,
		f.r.OrganizationID, f.initial.EventID).Scan(&snapshot)
	if err != nil {
		t.Fatal("read original creation evidence", err)
	}
	return snapshot // Compare only in memory, never print payloads or MACs.
}

func TestIntegrationReviewRecoveryHistoricalAcknowledgement(t *testing.T) {
	for _, name := range []string{"first-actor", "second-actor"} {
		t.Run(name, func(t *testing.T) {
			f, request, want := completedReviewFixture(t, name, name == "second-actor")
			creationBefore := originalReviewCreation(t, f)
			before := recoverySnapshot(t, f.persistentFixture)
			r, identity := reviewRecoverer(t, f, f.db, request, nil)
			got, err := r.Recover(context.Background(), request, want.EnquiryID, 1, recoveredReviewKey)
			if err != nil || got != want || identity.calls.Load() != 1 {
				t.Fatal("historical review not recovered with fresh actor/request", err)
			}
			if recoverySnapshot(t, f.persistentFixture) != before {
				t.Fatal("recovery changed records")
			}
			// Advance authority revisions without revoking permission. Historic event
			// revisions deliberately no longer equal either current fence revision.
			tx := reviewRecoveryWriter(t, f, f.admin, request, true)
			commitAuthority(t, tx)
			var newer bool
			err = f.admin.QueryRow(context.Background(), `SELECT a.revision>v.actor_authority_revision AND o.revision>v.organization_authority_revision
 FROM softteros_enquiries.enquiry_events v JOIN softteros_access.actor_authority_fences a ON a.actor_id=v.actor_id
 JOIN softteros_access.organization_authority_fences o USING(organization_id) WHERE v.organization_id=$1 AND v.event_id=$2`,
				want.OrganizationID, want.EventID).Scan(&newer)
			if err != nil || !newer {
				t.Fatal("historical/current revision control failed", err)
			}
			// Test-only historical qualification fixture. No qualification operation
			// or reassignment is added, and all existing integrity constraints apply.
			_, history := namedFixture(3, "review-recovery-later", want.OrganizationID)
			qualified := history[2]
			qualified.EnquiryID, qualified.ActorID, qualified.MembershipID = want.EnquiryID, request.ActorID, request.MembershipID
			qualified.Assignee, qualified.PreviousAssignee = text(request.MembershipID), text(request.MembershipID)
			qualified.At = stamp(want.At.Add(time.Microsecond))
			tx = beginAssignedFixtureTx(t, f.admin)
			if err = advance(context.Background(), tx, qualified); err != nil {
				t.Fatal("later qualification fixture", err)
			}
			commitAuthority(t, tx)
			var state string
			var version int64
			if err = f.admin.QueryRow(context.Background(), "SELECT state,version FROM softteros_enquiries.enquiries WHERE organization_id=$1 AND enquiry_id=$2", want.OrganizationID, want.EnquiryID).Scan(&state, &version); err != nil || state != "Qualified" || version != 3 {
				t.Fatal("qualification positive control failed", err)
			}
			before = recoverySnapshot(t, f.persistentFixture)
			for _, attempt := range []string{"after-qualification", "repeat-historical"} {
				request.RequestID = attempt
				r, identity = reviewRecoverer(t, f, f.db, request, nil)
				got, err = r.Recover(context.Background(), request, want.EnquiryID, 1, recoveredReviewKey)
				if err != nil || got != want || identity.calls.Load() != 1 {
					t.Fatal("recovery depended on current state/revision or lost attribution", err)
				}
			}
			if recoverySnapshot(t, f.persistentFixture) != before || originalReviewCreation(t, f) != creationBefore || f.events.Load() != 1 || f.ids.Load() != 2 {
				t.Fatal("recovery wrote or replaced historical evidence")
			}
		})
	}
}

func TestIntegrationReviewRecoveryDenials(t *testing.T) {
	for _, mode := range []string{"revoked-grant", "expired-grant", "inactive-grant", "replacement", "ambiguity", "member-revoked", "member-expired", "member-inactive", "no-review", "admin", "identity-disabled", "stale-attestation", "nonhuman", "identity-unavailable", "wrong-key"} {
		t.Run(mode, func(t *testing.T) {
			f, request, want := completedReviewFixture(t, "deny-"+mode, false)
			r, identity := reviewRecoverer(t, f, f.db, request, nil)
			tx := reviewRecoveryWriter(t, f, f.admin, request, mode == "identity-disabled")
			switch mode {
			case "revoked-grant", "replacement":
				execAuthority(t, tx, "UPDATE softteros_access.enquiry_transition_grants SET revoked=true WHERE organization_id=$1 AND grant_id='original-grant'", request.OrganizationID)
			case "expired-grant":
				execAuthority(t, tx, "UPDATE softteros_access.enquiry_transition_grants SET valid_until=clock_timestamp() WHERE organization_id=$1 AND grant_id='original-grant'", request.OrganizationID)
			case "inactive-grant":
				execAuthority(t, tx, "UPDATE softteros_access.enquiry_transition_grants SET active=false WHERE organization_id=$1 AND grant_id='original-grant'", request.OrganizationID)
			case "member-revoked":
				execAuthority(t, tx, "UPDATE softteros_access.memberships SET revoked=true WHERE organization_id=$1 AND membership_id=$2", request.OrganizationID, request.MembershipID)
			case "member-expired":
				execAuthority(t, tx, "UPDATE softteros_access.memberships SET valid_until=clock_timestamp() WHERE organization_id=$1 AND membership_id=$2", request.OrganizationID, request.MembershipID)
			case "member-inactive":
				execAuthority(t, tx, "UPDATE softteros_access.memberships SET active=false WHERE organization_id=$1 AND membership_id=$2", request.OrganizationID, request.MembershipID)
			case "no-review", "admin":
				execAuthority(t, tx, "DELETE FROM softteros_access.membership_enquiry_capabilities WHERE organization_id=$1 AND membership_id=$2 AND capability='enquiries.review'", request.OrganizationID, request.MembershipID)
				execAuthority(t, tx, "INSERT INTO softteros_access.membership_enquiry_capabilities VALUES($1,$2,'enquiries.read'),($1,$2,'enquiries.qualify')", request.OrganizationID, request.MembershipID)
			case "identity-disabled":
				identity.enabled.Store(false)
			}
			if mode == "replacement" || mode == "ambiguity" {
				insertReviewFixtureGrant(t, tx, request, "replacement-grant", want.EnquiryID, authz.CapabilityReviewEnquiry)
			}
			commitAuthority(t, tx)
			expected := authz.ErrTransitionUnauthorized
			switch mode {
			case "admin":
				r.db = f.db
			case "wrong-key":
				r.secret[0] ^= 1
				expected = ErrReviewMismatch
			case "stale-attestation", "nonhuman", "identity-unavailable":
				r.identity = reviewIdentityFunc(func(_ context.Context, q ReviewIdentityRequest) (ReviewAttestation, error) {
					a := ReviewAttestation{Actor: authz.Actor{ID: q.ActorID, Authenticated: true, Human: true}, RequestID: q.RequestID}
					if mode == "stale-attestation" {
						a.RequestID = f.request.RequestID
					}
					if mode == "nonhuman" {
						a.Actor.Human = false
					}
					if mode == "identity-unavailable" {
						return ReviewAttestation{}, errors.New("private provider diagnostic")
					}
					return a, nil
				})
				if mode == "identity-unavailable" {
					expected = ErrReviewAuthorityUnavailable
				}
			}
			before := recoverySnapshot(t, f.persistentFixture)
			got, err := r.Recover(context.Background(), request, want.EnquiryID, 1, recoveredReviewKey)
			noStartedReview(t, got, err, expected)
			if err.Error() != expected.Error() || recoverySnapshot(t, f.persistentFixture) != before || f.events.Load() != 1 {
				t.Fatal("denial leaked details or modified records", err)
			}
		})
	}
}

func TestIntegrationReviewRecoveryScopeIsolation(t *testing.T) {
	f, request, want := completedReviewFixture(t, "scope", false)
	foreign, foreignRequest, foreignWant := completedReviewFixture(t, "foreign", true)
	other := f.otherReviewer(t)
	f.grant(t, other, "other-actor-grant", want.EnquiryID)
	second := request
	second.MembershipID = "second-member"
	tx := reviewRecoveryWriter(t, f, f.admin, request, false)
	execAuthority(t, tx, "INSERT INTO softteros_access.memberships VALUES($1,$2,$3,true,false,'2000-01-01+00','9999-01-01+00')", second.OrganizationID, second.MembershipID, second.ActorID)
	commitAuthority(t, tx)
	f.grant(t, second, "second-member-grant", want.EnquiryID)
	otherEnquiry := f.capture(t, "other-target").Enquiry.ID()
	f.grant(t, request, "other-target-grant", otherEnquiry)
	before, foreignBefore := recoverySnapshot(t, f.persistentFixture), recoverySnapshot(t, foreign.persistentFixture)
	wrongActor := request
	wrongActor.ActorID = other.ActorID
	wrongOrg := request
	wrongOrg.OrganizationID = foreignRequest.OrganizationID
	for _, tc := range []struct {
		name    string
		request ReviewRequest
		id, key string
		want    error
	}{
		{"wrong actor/member", wrongActor, want.EnquiryID, recoveredReviewKey, authz.ErrTransitionUnauthorized},
		{"wrong active org", wrongOrg, want.EnquiryID, recoveredReviewKey, authz.ErrTransitionUnauthorized},
		{"other actor", other, want.EnquiryID, recoveredReviewKey, ErrReviewUnconfirmed},
		{"other membership", second, want.EnquiryID, recoveredReviewKey, ErrReviewUnconfirmed},
		{"cross tenant", request, foreignWant.EnquiryID, recoveredReviewKey, authz.ErrTransitionUnauthorized},
		{"missing target", request, "absent-enquiry", recoveredReviewKey, authz.ErrTransitionUnauthorized},
		{"other authorized target", request, otherEnquiry, recoveredReviewKey, ErrReviewUnconfirmed},
		{"absent key", request, want.EnquiryID, "absent-key", ErrReviewUnconfirmed},
		{"creation key", request, want.EnquiryID, reviewCreationKey, ErrReviewUnconfirmed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.request.RequestID = "scope-recovery"
			r, _ := reviewRecoverer(t, f, f.db, tc.request, nil)
			got, err := r.Recover(context.Background(), tc.request, tc.id, 1, tc.key)
			noStartedReview(t, got, err, tc.want)
		})
	}
	foreignRequest.RequestID = "foreign-own-recovery"
	r, _ := reviewRecoverer(t, foreign, foreign.db, foreignRequest, nil)
	got, err := r.Recover(context.Background(), foreignRequest, foreignWant.EnquiryID, 1, recoveredReviewKey)
	if err != nil || got != foreignWant {
		t.Fatal("independently authorized foreign scope positive control", err)
	}
	if recoverySnapshot(t, f.persistentFixture) != before || recoverySnapshot(t, foreign.persistentFixture) != foreignBefore {
		t.Fatal("scope probes changed records")
	}
}

func TestIntegrationReviewRecoveryConcurrentVisibility(t *testing.T) {
	for _, stage := range []string{"pending", "complete"} {
		for _, outcome := range []string{"commit", "rollback"} {
			t.Run(stage+"-"+outcome, func(t *testing.T) {
				f := newReviewFixture(t, "recover-visibility-"+stage+"-"+outcome)
				id := f.initial.Enquiry.ID()
				f.grant(t, f.request, "original-grant", id)
				before := recoverySnapshot(t, f.persistentFixture)
				creationBefore := originalReviewCreation(t, f)
				peer, _, _ := database(t)
				paused, release, resume := pauseWriter(t)
				defer resume()
				target := reserveReviewSQL
				if stage == "complete" {
					target = reviewIntegritySQL
				}
				starter := f.starter(t, f.db, f.request, func(e pg.Executor) pg.Executor {
					return &persistentObserved{Executor: e, after: func(ctx context.Context, q string, _ []any) error {
						if q != target {
							return nil
						}
						if err := pauseAt(ctx, paused, release); err != nil {
							return err
						}
						if outcome == "rollback" {
							return errors.New("controlled pre-commit rollback")
						}
						return nil
					}}
				})
				ctx, end := context.WithTimeout(context.Background(), 10*time.Second)
				defer end()
				done := startReviewAttempt(t, ctx, starter, f.request, id, recoveredReviewKey)
				reachedWrite(t, paused)
				request := f.request
				request.RequestID = "recover-in-flight"
				r, _ := reviewRecoverer(t, f, peer, request, nil)
				probe, cancel := context.WithTimeout(ctx, 3*time.Second)
				got, err := r.Recover(probe, request, id, 1, recoveredReviewKey)
				cancel()
				noStartedReview(t, got, err, ErrReviewUnconfirmed)
				creationCounts(t, f.persistentFixture, [3]int{1, 1, 1})
				resume()
				prior := completedReview(t, done)
				request.RequestID = "recover-after-completion"
				r, _ = reviewRecoverer(t, f, peer, request, nil)
				got, err = r.Recover(ctx, request, id, 1, recoveredReviewKey)
				if outcome == "commit" {
					if prior.err != nil || err != nil || got != prior.result {
						t.Fatal("committed review not recoverable", prior.err, err)
					}
					f.assertCommitted(t, f.request, "original-grant", recoveredReviewKey, got)
					creationCounts(t, f.persistentFixture, [3]int{1, 2, 2})
				} else {
					noStartedReview(t, prior.result, prior.err, ErrStorage)
					noStartedReview(t, got, err, ErrReviewUnconfirmed)
					if recoverySnapshot(t, f.persistentFixture) != before {
						t.Fatal("rolled-back review left writes")
					}
				}
				if originalReviewCreation(t, f) != creationBefore || f.ids.Load() != 2 {
					t.Fatal("recovery touched creation evidence")
				}
			})
		}
	}
}

func TestIntegrationReviewRecoveryFinalEligibility(t *testing.T) {
	for _, mode := range []string{"grant-expiry", "member-expiry", "overlap", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			f, request, want := completedReviewFixture(t, "final-"+mode, false)
			before := recoverySnapshot(t, f.persistentFixture)
			tx := reviewRecoveryWriter(t, f, f.admin, request, false)
			var at time.Time
			if err := tx.QueryRow(context.Background(), "SELECT clock_timestamp()+interval '2 seconds'").Scan(&at); err != nil {
				t.Fatal(err)
			}
			if mode == "grant-expiry" || mode == "replacement" {
				execAuthority(t, tx, "UPDATE softteros_access.enquiry_transition_grants SET valid_until=$2 WHERE organization_id=$1 AND grant_id='original-grant'", request.OrganizationID, at)
			}
			if mode == "member-expiry" {
				execAuthority(t, tx, "UPDATE softteros_access.memberships SET valid_until=$3 WHERE organization_id=$1 AND membership_id=$2", request.OrganizationID, request.MembershipID, at)
			}
			if mode == "overlap" || mode == "replacement" {
				insertReviewFixtureGrant(t, tx, request, "later-grant", want.EnquiryID, authz.CapabilityReviewEnquiry)
				execAuthority(t, tx, "UPDATE softteros_access.enquiry_transition_grants SET valid_from=$2 WHERE organization_id=$1 AND grant_id='later-grant'", request.OrganizationID, at)
			}
			commitAuthority(t, tx)
			paused, release, resume := pauseWriter(t)
			defer resume()
			r, _ := reviewRecoverer(t, f, f.db, request, observeAssignedRead(nil, func(ctx context.Context, q string, _ pg.Executor) error {
				if q == recoverReviewSQL {
					return pauseAt(ctx, paused, release)
				}
				return nil
			}))
			ctx, end := context.WithTimeout(context.Background(), 10*time.Second)
			defer end()
			done := startAssignedReadWork(t, func() reviewCompletion {
				got, err := r.Recover(ctx, request, want.EnquiryID, 1, recoveredReviewKey)
				return reviewCompletion{got, err}
			})
			reachedWrite(t, paused)
			waitReviewClock(t, f.admin, at)
			resume()
			got := completedReview(t, done)
			noStartedReview(t, got.result, got.err, authz.ErrTransitionUnauthorized)
			if recoverySnapshot(t, f.persistentFixture) != before {
				t.Fatal("expired recovery changed history")
			}
		})
	}
}

func TestIntegrationReviewRecoveryRevocationOrdering(t *testing.T) {
	for _, first := range []bool{true, false} {
		name := "recovery-first"
		if first {
			name = "revocation-first"
		}
		t.Run(name, func(t *testing.T) {
			f, request, want := completedReviewFixture(t, name, false)
			before := recoverySnapshot(t, f.persistentFixture)
			peer := assignedReadPeer(t, &assignedReadFixture{persistentFixture: f.persistentFixture})
			ctx, end := context.WithTimeout(context.Background(), 10*time.Second)
			defer end()
			pid := make(chan uint32, 1)
			if first {
				writer := reviewRecoveryWriter(t, f, peer, request, false)
				execAuthority(t, writer, "UPDATE softteros_access.enquiry_transition_grants SET revoked=true WHERE organization_id=$1 AND grant_id='original-grant'", request.OrganizationID)
				r, identity := reviewRecoverer(t, f, f.db, request, observeAssignedRead(assignedReadPID(creationFenceSQL, pid), nil))
				done := startAssignedReadWork(t, func() reviewCompletion {
					got, err := r.Recover(ctx, request, want.EnquiryID, 1, recoveredReviewKey)
					return reviewCompletion{got, err}
				})
				waitAssignedBlocked(t, f.admin, authorityPID(t, pid), peer.PgConn().PID())
				if identity.calls.Load() != 0 {
					t.Fatal("identity checked before acquiring fences")
				}
				commitAuthority(t, writer)
				got := completedReview(t, done)
				noStartedReview(t, got.result, got.err, authz.ErrTransitionUnauthorized)
			} else {
				paused, release, resume := pauseWriter(t)
				defer resume()
				r, _ := reviewRecoverer(t, f, f.db, request, observeAssignedRead(nil, func(ctx context.Context, q string, e pg.Executor) error {
					if q != recoverReviewSQL {
						return nil
					}
					if err := assignedReadPID(q, pid)(ctx, q, e); err != nil {
						return err
					}
					return pauseAt(ctx, paused, release)
				}))
				done := startAssignedReadWork(t, func() reviewCompletion {
					got, err := r.Recover(ctx, request, want.EnquiryID, 1, recoveredReviewKey)
					return reviewCompletion{got, err}
				})
				reachedWrite(t, paused)
				writerDone := startAssignedReadWork(t, func() error { return revokeAfterFences(ctx, peer, f.persistentFixture, authz.CapabilityReviewEnquiry) })
				waitAssignedBlocked(t, f.admin, peer.PgConn().PID(), authorityPID(t, pid))
				resume()
				got := completedReview(t, done)
				if got.err != nil || got.result != want {
					t.Fatal("recovery ordered first failed", got.err)
				}
				if err := authorityResult(t, writerDone); err != nil {
					t.Fatal("revocation did not follow recovery completion", err)
				}
				request.RequestID = "after-recovery-revocation"
				r, _ = reviewRecoverer(t, f, f.db, request, nil)
				ack, err := r.Recover(ctx, request, want.EnquiryID, 1, recoveredReviewKey)
				noStartedReview(t, ack, err, authz.ErrTransitionUnauthorized)
			}
			if recoverySnapshot(t, f.persistentFixture) != before {
				t.Fatal("revocation/recovery changed business records")
			}
		})
	}
}

func TestIntegrationReviewRecoveryFailures(t *testing.T) {
	for _, mode := range []string{"query", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f, request, want := completedReviewFixture(t, "failure-"+mode, false)
			before := recoverySnapshot(t, f.persistentFixture)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var beforePID, afterPID uint32
			var sqlstate string
			r, _ := reviewRecoverer(t, f, f.db, request, observeAssignedRead(func(ctx context.Context, q string, e pg.Executor) error {
				if q != recoverReviewSQL {
					return nil
				}
				if err := e.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&beforePID); err != nil {
					return err
				}
				if mode == "query" {
					_, err := e.Exec(ctx, "SELECT 1/0")
					var server *pgconn.PgError
					if errors.As(err, &server) {
						sqlstate = server.Code
					}
					return err
				}
				return nil
			}, func(_ context.Context, q string, _ pg.Executor) error {
				if q == recoverReviewSQL && mode == "cancel" {
					cancel()
				}
				return nil
			}))
			got, err := r.Recover(ctx, request, want.EnquiryID, 1, recoveredReviewKey)
			if mode == "cancel" {
				noStartedReview(t, got, err, context.Canceled)
			} else {
				noStartedReview(t, got, err, ErrStorage)
				if sqlstate != "22012" || err.Error() != ErrStorage.Error() {
					t.Fatal("wrong/sensitive storage failure", err)
				}
			}
			if errors.Is(err, pg.ErrCleanup) || recoverySnapshot(t, f.persistentFixture) != before {
				t.Fatal("recovery failure was not clean", err)
			}
			err = f.db.WithTx(context.Background(), pg.Scope{ActorID: request.ActorID, OrganizationID: request.OrganizationID}, func(ctx context.Context, e pg.Executor) error {
				return e.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&afterPID)
			})
			if err != nil || beforePID == 0 || beforePID != afterPID {
				t.Fatal("healthy recovery backend not reused", err)
			}
		})
	}
}

func TestIntegrationReviewRecoveryCommitTransport(t *testing.T) {
	for _, mode := range []commitWireMode{deliverCommitReply, dropCommitReply, dropCommitQuery} {
		t.Run(string(mode), func(t *testing.T) {
			f := newReviewFixture(t, "recover-wire-"+string(mode))
			id := f.initial.Enquiry.ID()
			f.grant(t, f.request, "original-grant", id)
			initial := recoverySnapshot(t, f.persistentFixture)
			creationBefore := originalReviewCreation(t, f)
			ctx, end := context.WithTimeout(context.Background(), 20*time.Second)
			defer end()
			target := f.admin.Config()
			cfg := pg.DefaultConfig(target.Host, target.Port, target.Database, target.User)
			cfg.MaxConns = 1
			wire := newCommitWireProxy(t, ctx, cfg, mode)
			cfg.Host = wire.dir
			db, err := pg.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := db.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			starter := f.starter(t, db, f.request, nil)
			done := startReviewAttempt(t, ctx, starter, f.request, id, recoveredReviewKey)
			var point commitWirePoint
			select {
			case point = <-wire.reached:
			case got := <-done:
				t.Fatal("review finished before COMMIT wire boundary", got.err)
			case <-wire.done:
				t.Fatal("proxy stopped early", wire.relayError())
			case <-ctx.Done():
				t.Fatal("review COMMIT did not reach proxy")
			}
			committed := mode != dropCommitQuery
			ready := byte('T')
			counts := [3]int{1, 1, 1}
			if committed {
				ready = 'I'
				counts = [3]int{1, 2, 2}
			}
			if point.pid <= 0 || point.queryForwarded != committed || point.ready != ready || (point.replyKinds != "") != committed {
				t.Fatal("wrong review COMMIT fault boundary")
			}
			assertCommitWireObserver(t, ctx, f.persistentFixture, point.pid, !committed)
			var want StartedReview
			if committed {
				want = StartedReview{OrganizationID: f.request.OrganizationID, EnquiryID: id, EventID: id + "-review-1", State: enquiries.StateUnderReview, Version: 2, AssigneeMembershipID: f.request.MembershipID}
				err = f.admin.QueryRow(ctx, `SELECT v.at::timestamptz FROM softteros_enquiries.enquiry_events v
 JOIN softteros_enquiries.enquiries e ON e.organization_id=v.organization_id AND e.enquiry_id=v.enquiry_id
 WHERE v.organization_id=$1 AND v.event_id=$2 AND v.enquiry_id=$3 AND v.action='enquiry.review_started'
 AND e.state='Under review' AND e.version=2 AND e.assignee_membership_id=$4 AND e.last_changed_at=v.at`, want.OrganizationID, want.EventID, id, want.AssigneeMembershipID).Scan(&want.At)
				if err != nil {
					t.Fatal("observer did not see committed review", err)
				}
				want.At = want.At.UTC()
				f.assertCommitted(t, f.request, "original-grant", recoveredReviewKey, want)
			}
			creationCounts(t, f.persistentFixture, counts)
			select {
			case got := <-done:
				t.Fatal("review returned before held reply release", got.err)
			default:
			}
			close(wire.release)
			result := completedReview(t, done)
			if mode == deliverCommitReply {
				if result.err != nil || result.result != want {
					t.Fatal("normal review COMMIT control failed", result.err)
				}
			} else {
				noStartedReview(t, result.result, result.err, pg.ErrCommitUnknown)
				if result.err != pg.ErrCommitUnknown || ctx.Err() != nil {
					t.Fatal("transport loss did not retain conservative commit outcome", result.err)
				}
				waitCommitWireBackendGone(t, f.persistentFixture, point.pid)
			}
			creationCounts(t, f.persistentFixture, counts)
			if !committed && recoverySnapshot(t, f.persistentFixture) != initial {
				t.Fatal("dropped COMMIT survived backend exit")
			}
			if originalReviewCreation(t, f) != creationBefore {
				t.Fatal("review fault altered original creation")
			}
			var healthyPID int32
			err = db.WithTx(ctx, pg.Scope{ActorID: f.request.ActorID, OrganizationID: f.request.OrganizationID}, func(ctx context.Context, e pg.Executor) error {
				if err := restricted(ctx, e, f.role); err != nil {
					return err
				}
				return e.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&healthyPID)
			})
			if err != nil || healthyPID <= 0 || (healthyPID == point.pid) != (mode == deliverCommitReply) {
				t.Fatal("faulted review backend was reused or access failed", err)
			}
			before := recoverySnapshot(t, f.persistentFixture)
			request := f.request
			for _, attempt := range []string{"recover-wire-first", "recover-wire-repeat"} {
				request.RequestID = attempt
				r, identity := reviewRecoverer(t, f, db, request, nil)
				ack, err := r.Recover(ctx, request, id, 1, recoveredReviewKey)
				if identity.calls.Load() != 1 {
					t.Fatal("recovery omitted fresh attestation")
				}
				if committed {
					if err != nil || ack != want {
						t.Fatal("lost review reply not recovered", err)
					}
				} else {
					noStartedReview(t, ack, err, ErrReviewUnconfirmed)
				}
			}
			request.RequestID, request.MembershipID = "recover-wire-denied", "unbound-member"
			r, _ := reviewRecoverer(t, f, db, request, nil)
			ack, err := r.Recover(ctx, request, id, 1, recoveredReviewKey)
			noStartedReview(t, ack, err, authz.ErrTransitionUnauthorized)
			if recoverySnapshot(t, f.persistentFixture) != before || originalReviewCreation(t, f) != creationBefore || f.events.Load() != 1 || f.ids.Load() != 2 {
				t.Fatal("review recovery rewrote records or retried")
			}
			if err := db.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			wire.cancel()
			select {
			case <-wire.done:
			case <-time.After(3 * time.Second):
				t.Fatal("review proxy cleanup timed out")
			}
			if err := wire.relayError(); err != nil {
				t.Fatal(err)
			}
			sessions, replies := 2, 0
			if mode == deliverCommitReply {
				sessions, replies = 1, len(point.replyKinds)
			}
			if len(wire.sessions) != sessions || wire.sessions[0].pid != point.pid || wire.sessions[sessions-1].pid != healthyPID || wire.sessions[0].replyFrames != replies {
				t.Fatal("wrong session/response delivery evidence")
			}
			for _, session := range wire.sessions {
				waitCommitWireBackendGone(t, f.persistentFixture, session.pid)
			}
			t.Logf("review COMMIT forwarded=%t reply=%q ready=%c delivered=%d committed records=%v client=%v sessions=%d all sessions/locks released", point.queryForwarded, point.replyKinds, point.ready, replies, counts, result.err, sessions)
		})
	}
}
