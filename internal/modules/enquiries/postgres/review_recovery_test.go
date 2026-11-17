package postgres

import (
	"context"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

var reviewRecoveryRequest = ReviewRequest{"actor-17", "org-29", "member-31", "recovery-attempt"}

type reviewRecoveryScript struct {
	*creationScript
	receipt             reviewReceipt
	grant               authz.EnquiryTransitionGrant
	finalGrant          string
	queryErr, finishErr error
	calls               int
}

func (s *reviewRecoveryScript) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("review recovery attempted a write or transaction-control statement")
}

func (s *reviewRecoveryScript) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	if q != recoverReviewSQL && q != creationFactsSQL {
		return s.creationScript.QueryRow(ctx, q, args...)
	}
	return creationRow(func(dest ...any) error {
		if q == creationFactsSQL {
			if !reflect.DeepEqual(args, []any{"actor-17", "org-29", "member-31", "enquiries.review"}) {
				panic("wrong review authority binding")
			}
			s.order = append(s.order, "facts")
			*dest[0].(*string), *dest[1].(*string), *dest[2].(*string) = s.actor, s.org, s.member
			*dest[3].(*string), *dest[4].(*string) = s.memberActor, s.memberOrg
			*dest[5].(*bool), *dest[6].(*bool) = s.active, s.revoked
			*dest[7].(*pgtype.Timestamptz), *dest[8].(*pgtype.Timestamptz) = s.from, s.until
			*dest[9].(*bool) = s.capability
			return nil
		}
		if !reflect.DeepEqual(args, []any{"org-29", "member-31", "original-review-key", "actor-17", "enquiry-71", "enquiries.review"}) {
			panic("wrong review receipt binding")
		}
		s.order = append(s.order, "receipt")
		if s.queryErr != nil {
			return s.queryErr
		}
		r := s.receipt
		values := []any{r.enquiryID, r.eventID, r.command, r.expectedVersion, r.resultingVersion,
			r.fingerprintVersion, r.fingerprint, r.completed, r.completedAt, r.at, r.grantID, r.assignee, r.resourceMatches}
		if len(dest) != len(values) {
			panic("unexpected review receipt projection")
		}
		for i, value := range values {
			reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(value))
		}
		return nil
	})
}

type reviewRecoveryGrantRows struct {
	pgx.Rows
	grant authz.EnquiryTransitionGrant
	read  bool
}

func (r *reviewRecoveryGrantRows) Next() bool {
	if r.read {
		return false
	}
	r.read = true
	return true
}
func (r *reviewRecoveryGrantRows) Close()     {}
func (r *reviewRecoveryGrantRows) Err() error { return nil }
func (r *reviewRecoveryGrantRows) Scan(dest ...any) error {
	g := r.grant
	values := []any{g.ID, g.OrganizationID, g.ActorID, g.MembershipID, g.EnquiryID, string(g.Capability), g.Active, g.Revoked, stamp(g.ValidFrom), stamp(g.ValidUntil)}
	for i, value := range values {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(value))
	}
	return nil
}
func (s *reviewRecoveryScript) Query(_ context.Context, q string, args ...any) (pgx.Rows, error) {
	at := s.action.Time
	if s.clocks > 1 {
		at = s.final.Time
	}
	if q != eligibleReviewGrantSQL || !reflect.DeepEqual(args, []any{"org-29", "actor-17", "member-31", "enquiry-71", "enquiries.review", at}) {
		panic("unexpected review grant query or stale time")
	}
	s.order = append(s.order, "grants")
	g := s.grant
	if s.clocks > 1 && s.finalGrant != "" {
		g.ID = s.finalGrant
	}
	return &reviewRecoveryGrantRows{grant: g}, nil
}

func simulatedReviewRecovery(t *testing.T) (*ReviewStarter, *reviewRecoveryScript, StartedReview) {
	t.Helper()
	s := &reviewRecoveryScript{creationScript: script(), grant: authz.EnquiryTransitionGrant{
		ID: "original-grant", OrganizationID: "org-29", ActorID: "actor-17", MembershipID: "member-31", EnquiryID: "enquiry-71",
		Capability: authz.CapabilityReviewEnquiry, Active: true, ValidFrom: created.Add(-time.Hour), ValidUntil: created.Add(time.Hour),
	}}
	identity := reviewIdentityFunc(func(_ context.Context, request ReviewIdentityRequest) (ReviewAttestation, error) {
		if request != (ReviewIdentityRequest{"actor-17", "recovery-attempt"}) || !reflect.DeepEqual(s.order, []string{"fences"}) {
			t.Fatal("attestation was not fresh/request-bound after fences")
		}
		s.order = append(s.order, "identity")
		return ReviewAttestation{Actor: authz.Actor{ID: request.ActorID, Authenticated: true, Human: true}, RequestID: request.RequestID}, nil
	})
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	r, err := NewReviewStarter(&pg.DB{}, identity, secret[:], func() (string, error) { t.Fatal("recovery generated an event ID"); return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	r.db = recoveryBoundaryFunc(func(ctx context.Context, scope pg.Scope, fn func(context.Context, pg.Executor) error) error {
		s.calls++
		if scope != (pg.Scope{OrganizationID: "org-29", ActorID: "actor-17"}) {
			t.Fatal("wrong recovery scope")
		}
		if err := fn(ctx, s); err != nil {
			return err
		}
		return s.finishErr // Completion-error simulation, not a transport fault.
	})
	proof := reviewProof(t, "org-29", "actor-17", "member-31", "enquiry-71", "original-grant", authz.CapabilityReviewEnquiry, created)
	mac, err := reviewFingerprint(secret, proof, "enquiry-71", "original-review-key")
	if err != nil {
		t.Fatal(err)
	}
	originalAt := created.Add(-time.Minute)
	s.receipt = reviewReceipt{enquiryID: text("enquiry-71"), eventID: text("original-event"), command: "enquiry.review_started", expectedVersion: 1,
		resultingVersion: pgtype.Int8{Int64: 2, Valid: true}, fingerprintVersion: 1, fingerprint: mac[:], completed: true,
		completedAt: stamp(originalAt.Add(time.Microsecond)), at: stamp(originalAt), grantID: text("original-grant"), assignee: text("member-31"), resourceMatches: true}
	return r, s, StartedReview{OrganizationID: "org-29", EnquiryID: "enquiry-71", EventID: "original-event", State: enquiries.StateUnderReview, Version: 2, AssigneeMembershipID: "member-31", At: originalAt}
}

func TestReviewRecoveryOrderingAndHistoricalResult(t *testing.T) {
	r, s, want := simulatedReviewRecovery(t)
	got, err := r.Recover(context.Background(), reviewRecoveryRequest, "enquiry-71", 1, "original-review-key")
	if err != nil || got != want || s.calls != 1 {
		t.Fatal("wrong historical review acknowledgement", err)
	}
	if !reflect.DeepEqual(s.order, []string{"fences", "identity", "facts", "clock", "grants", "receipt", "clock", "grants"}) {
		t.Fatal("recovery omitted/reordered authority", s.order)
	}
}

func TestReviewRecoverySafeOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*reviewRecoveryScript)
		want error
	}{
		{"absent", func(s *reviewRecoveryScript) { s.queryErr = pgx.ErrNoRows }, ErrReviewUnconfirmed},
		{"query failure", func(s *reviewRecoveryScript) { s.queryErr = errors.New("private database details") }, ErrStorage},
		{"mismatch", func(s *reviewRecoveryScript) { s.receipt.fingerprint[0] ^= 1 }, ErrReviewMismatch},
		{"missing capability", func(s *reviewRecoveryScript) { s.capability = false }, authz.ErrTransitionUnauthorized},
		{"exact membership expiry after lookup", func(s *reviewRecoveryScript) { s.until = s.final }, authz.ErrTransitionUnauthorized},
		{"exact grant expiry after lookup", func(s *reviewRecoveryScript) { s.grant.ValidUntil = s.final.Time }, authz.ErrTransitionUnauthorized},
		{"expired mismatch", func(s *reviewRecoveryScript) { s.receipt.fingerprint[0] ^= 1; s.until = s.final }, authz.ErrTransitionUnauthorized},
		{"replacement grant", func(s *reviewRecoveryScript) { s.grant.ID = "replacement" }, authz.ErrTransitionUnauthorized},
		{"grant changes after lookup", func(s *reviewRecoveryScript) { s.finalGrant = "replacement" }, authz.ErrTransitionUnauthorized},
		{"unsupported encoding", func(s *reviewRecoveryScript) { s.receipt.fingerprintVersion = 2 }, ErrStored},
		{"short MAC", func(s *reviewRecoveryScript) { s.receipt.fingerprint = s.receipt.fingerprint[:31] }, ErrStored},
		{"wrong command", func(s *reviewRecoveryScript) { s.receipt.command = "enquiry.qualified" }, ErrStored},
		{"wrong expected version", func(s *reviewRecoveryScript) { s.receipt.expectedVersion = 2 }, ErrStored},
		{"wrong result version", func(s *reviewRecoveryScript) { s.receipt.resultingVersion.Int64 = 3 }, ErrStored},
		{"missing resource", func(s *reviewRecoveryScript) { s.receipt.resourceMatches = false }, ErrStored},
		{"invalid target", func(s *reviewRecoveryScript) { s.receipt.enquiryID = text("bad id") }, ErrStored},
		{"wrong target", func(s *reviewRecoveryScript) { s.receipt.enquiryID = text("other-enquiry") }, ErrStored},
		{"missing event", func(s *reviewRecoveryScript) { s.receipt.eventID = pgtype.Text{} }, ErrStored},
		{"invalid grant", func(s *reviewRecoveryScript) { s.receipt.grantID = text("bad id") }, ErrStored},
		{"wrong assignee", func(s *reviewRecoveryScript) { s.receipt.assignee = text("other-member") }, ErrStored},
		{"zero action time", func(s *reviewRecoveryScript) { s.receipt.at = stamp(time.Time{}) }, ErrStored},
		{"infinite completion time", func(s *reviewRecoveryScript) { s.receipt.completedAt.InfinityModifier = pgtype.Infinity }, ErrStored},
		{"precision loss", func(s *reviewRecoveryScript) { s.receipt.at.Time = s.receipt.at.Time.Add(time.Nanosecond) }, ErrStored},
		{"completion before action", func(s *reviewRecoveryScript) {
			s.receipt.completedAt = s.receipt.at
			s.receipt.completedAt.Time = s.receipt.at.Time.Add(-time.Microsecond)
		}, ErrStored},
		{"confirmed recovery rollback", func(s *reviewRecoveryScript) { s.finishErr = pg.ErrCommitRejected }, pg.ErrCommitRejected},
		{"uncertain recovery completion", func(s *reviewRecoveryScript) { s.finishErr = pg.ErrCommitUnknown }, pg.ErrCommitUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, s, _ := simulatedReviewRecovery(t)
			tc.edit(s)
			got, err := r.Recover(context.Background(), reviewRecoveryRequest, "enquiry-71", 1, "original-review-key")
			noStartedReview(t, got, err, tc.want)
			if err.Error() != tc.want.Error() || s.calls != 1 {
				t.Fatal("unsafe error or recovery retry", err)
			}
		})
	}
}

func TestReviewRecoveryPendingMetadata(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*reviewReceipt)
		want error
	}{
		{"valid pending", func(*reviewReceipt) {}, ErrReviewUnconfirmed},
		{"mismatch", func(r *reviewReceipt) { r.fingerprint[0] ^= 1 }, ErrReviewMismatch},
		{"missing target", func(r *reviewReceipt) { r.enquiryID = pgtype.Text{} }, ErrStored},
		{"missing resource", func(r *reviewReceipt) { r.resourceMatches = false }, ErrStored},
		{"wrong command", func(r *reviewReceipt) { r.command = "enquiry.created" }, ErrStored},
		{"wrong version", func(r *reviewReceipt) { r.expectedVersion = 0 }, ErrStored},
		{"unsupported encoding", func(r *reviewReceipt) { r.fingerprintVersion = 2 }, ErrStored},
		{"missing MAC", func(r *reviewReceipt) { r.fingerprint = nil }, ErrStored},
		{"event present", func(r *reviewReceipt) { r.eventID = text("partial-event") }, ErrStored},
		{"result present", func(r *reviewReceipt) { r.resultingVersion = pgtype.Int8{Int64: 2, Valid: true} }, ErrStored},
		{"completion present", func(r *reviewReceipt) { r.completedAt = stamp(created) }, ErrStored},
		{"event time present", func(r *reviewReceipt) { r.at = stamp(created) }, ErrStored},
		{"grant present", func(r *reviewReceipt) { r.grantID = text("original-grant") }, ErrStored},
		{"assignee present", func(r *reviewReceipt) { r.assignee = text("member-31") }, ErrStored},
		{"marked complete", func(r *reviewReceipt) { r.completed = true }, ErrStored},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, s, _ := simulatedReviewRecovery(t)
			// Pending rows cannot commit under the existing deferred constraints.
			// This exercises decoding without weakening those constraints.
			s.receipt = reviewReceipt{enquiryID: text("enquiry-71"), command: "enquiry.review_started", expectedVersion: 1, fingerprintVersion: 1, fingerprint: s.receipt.fingerprint, resourceMatches: true}
			tc.edit(&s.receipt)
			got, err := r.Recover(context.Background(), reviewRecoveryRequest, "enquiry-71", 1, "original-review-key")
			noStartedReview(t, got, err, tc.want)
		})
	}
}

func TestReviewRecoveryConfigurationAndSelectors(t *testing.T) {
	var r *ReviewStarter
	got, err := r.Recover(context.Background(), reviewRecoveryRequest, "enquiry-71", 1, "original-review-key")
	noStartedReview(t, got, err, ErrReviewConfiguration)
	r, s, _ := simulatedReviewRecovery(t)
	got, err = r.Recover(context.Background(), ReviewRequest{}, "enquiry-71", 1, "original-review-key")
	noStartedReview(t, got, err, authz.ErrTransitionUnauthorized)
	for _, tc := range []struct {
		id, key string
		version uint64
	}{{"bad id", "original-review-key", 1}, {"enquiry-71", "bad key", 1}, {"enquiry-71", "original-review-key", 0}, {"enquiry-71", "original-review-key", 2}} {
		got, err = r.Recover(context.Background(), reviewRecoveryRequest, tc.id, tc.version, tc.key)
		noStartedReview(t, got, err, ErrSelector)
	}
	if s.calls != 0 || len(s.order) != 0 {
		t.Fatal("invalid request reached storage")
	}
	for _, size := range []int{0, 31, 33} {
		if configured, err := NewReviewStarter(&pg.DB{}, r.identity, make([]byte, size), r.newEventID); configured != nil || err != ErrReviewConfiguration {
			t.Fatal("invalid recovery key accepted")
		}
	}
}
