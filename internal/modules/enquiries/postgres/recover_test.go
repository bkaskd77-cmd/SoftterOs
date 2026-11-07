package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type recoveryBoundaryFunc func(context.Context, pg.Scope, func(context.Context, pg.Executor) error) error

func (f recoveryBoundaryFunc) WithTx(ctx context.Context, scope pg.Scope, fn func(context.Context, pg.Executor) error) error {
	return f(ctx, scope, fn)
}

type recoveryScript struct {
	*creationScript
	receipt             creationReceipt
	queryErr, finishErr error
}

func (s *recoveryScript) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	if q != recoverCreationSQL {
		return s.creationScript.QueryRow(ctx, q, args...)
	}
	return creationRow(func(dest ...any) error {
		if !reflect.DeepEqual(args, []any{"org-29", "member-31", "original-key", "actor-17", "enquiries.create"}) {
			panic("wrong recovery binding")
		}
		s.order = append(s.order, "receipt")
		if s.queryErr != nil {
			return s.queryErr
		}
		r := s.receipt
		*dest[0].(*pgtype.Text), *dest[1].(*pgtype.Text) = r.enquiryID, r.eventID
		*dest[2].(*string), *dest[3].(*int64), *dest[4].(*pgtype.Int8) = r.command, r.expectedVersion, r.resultingVersion
		*dest[5].(*int16), *dest[6].(*[]byte), *dest[7].(*bool) = r.fingerprintVersion, r.fingerprint, r.completed
		*dest[8].(*pgtype.Timestamptz), *dest[9].(*pgtype.Timestamptz), *dest[10].(*bool) = r.completedAt, r.at, r.resourceMatches
		return nil
	})
}

func simulatedRecovery(t *testing.T) (*FirstCreator, *recoveryScript, RecoveredCreation) {
	t.Helper()
	c, b, _ := simulatedCreator(t)
	mac, err := creationFingerprint(c.secret, fingerprintAuthority(t, "org-29", "actor-17", "member-31", created), "original-key", captureInput())
	if err != nil {
		t.Fatal(err)
	}
	originalAt := created.Add(-time.Minute)
	s := &recoveryScript{creationScript: b.tx.creationScript, receipt: creationReceipt{
		enquiryID: text("original-enquiry"), eventID: text("original-event"), command: "enquiry.created",
		resultingVersion: pgtype.Int8{Int64: 1, Valid: true}, fingerprintVersion: 1, fingerprint: mac[:],
		completed: true, completedAt: stamp(originalAt.Add(time.Microsecond)), at: stamp(originalAt), resourceMatches: true,
	}}
	c.authority.db = recoveryBoundaryFunc(func(ctx context.Context, scope pg.Scope, fn func(context.Context, pg.Executor) error) error {
		if scope != (pg.Scope{OrganizationID: "org-29", ActorID: "actor-17"}) {
			t.Fatal("recovery used the wrong transaction scope")
		}
		if err := fn(ctx, s); err != nil {
			return err
		}
		return s.finishErr
	})
	c.newID = func() (string, error) {
		t.Fatal("recovery generated an ID")
		return "", nil
	}
	return c, s, RecoveredCreation{OrganizationID: "org-29", EnquiryID: "original-enquiry", EventID: "original-event", Action: "enquiry.created", Version: 1, At: originalAt}
}

func requireRecoveryFailure(t *testing.T, got RecoveredCreation, err, want error) {
	t.Helper()
	if got != (RecoveredCreation{}) || !errors.Is(err, want) || errors.Is(err, pg.ErrCleanup) {
		t.Fatalf("expected zero acknowledgement and %v, got %v", want, err)
	}
}

func TestRecoveryChecksAuthorityBeforeAndAfterReceipt(t *testing.T) {
	for _, expired := range []bool{false, true} {
		c, s, want := simulatedRecovery(t)
		if expired {
			s.until = s.final
		}
		got, err := c.Recover(context.Background(), creationRequest, "original-key", captureInput())
		if expired {
			requireRecoveryFailure(t, got, err, authz.ErrUnauthorized)
		} else if err != nil || got != want {
			t.Fatal("historical acknowledgement differs", err)
		}
		if !reflect.DeepEqual(s.order, []string{"fences", "identity", "facts", "clock", "receipt", "clock"}) {
			t.Fatal("recovery omitted or reordered authority checks", s.order)
		}
	}
	c, s, _ := simulatedRecovery(t)
	s.capability = false
	got, err := c.Recover(context.Background(), creationRequest, "original-key", enquiries.Input{})
	requireRecoveryFailure(t, got, err, authz.ErrUnauthorized)
	if !reflect.DeepEqual(s.order, []string{"fences", "identity", "facts", "clock"}) {
		t.Fatal("denied recovery reached receipt lookup")
	}
}

func TestRecoverySafeOutcomeClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*recoveryScript)
		want error
	}{
		{"absent", func(s *recoveryScript) { s.queryErr = pgx.ErrNoRows }, ErrCreationUnconfirmed},
		{"query failure", func(s *recoveryScript) { s.queryErr = errors.New("private driver details") }, ErrStorage},
		{"mismatch", func(s *recoveryScript) { s.receipt.fingerprint[0] ^= 1 }, ErrCreationMismatch},
		{"expired mismatch", func(s *recoveryScript) { s.receipt.fingerprint[0] ^= 1; s.until = s.final }, authz.ErrUnauthorized},
		{"unsupported fingerprint version", func(s *recoveryScript) { s.receipt.fingerprintVersion = 2 }, ErrStored},
		{"missing fingerprint", func(s *recoveryScript) { s.receipt.fingerprint = nil }, ErrStored},
		{"incomplete stored receipt", func(s *recoveryScript) { s.receipt.completed = false }, ErrStored},
		{"wrong command", func(s *recoveryScript) { s.receipt.command = "enquiry.qualified" }, ErrStored},
		{"wrong expected version", func(s *recoveryScript) { s.receipt.expectedVersion = 1 }, ErrStored},
		{"wrong result version", func(s *recoveryScript) { s.receipt.resultingVersion.Int64 = 2 }, ErrStored},
		{"missing event", func(s *recoveryScript) { s.receipt.at = pgtype.Timestamptz{} }, ErrStored},
		{"invalid event id", func(s *recoveryScript) { s.receipt.eventID = text("bad id") }, ErrStored},
		{"missing enquiry binding", func(s *recoveryScript) { s.receipt.resourceMatches = false }, ErrStored},
		{"invalid completion instant", func(s *recoveryScript) { s.receipt.completedAt.Time = s.receipt.at.Time.Add(-time.Microsecond) }, ErrStored},
		{"recovery transaction completion unknown", func(s *recoveryScript) { s.finishErr = pg.ErrCommitUnknown }, pg.ErrCommitUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s, _ := simulatedRecovery(t)
			tc.edit(s)
			got, err := c.Recover(context.Background(), creationRequest, "original-key", captureInput())
			requireRecoveryFailure(t, got, err, tc.want)
			if err.Error() != tc.want.Error() {
				t.Fatal("recovery returned extra error details")
			}
		})
	}
}

func TestRecoveryPendingReservation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*recoveryScript)
		want error
	}{
		{"valid reservation", func(*recoveryScript) {}, ErrCreationUnconfirmed},
		{"fingerprint mismatch", func(s *recoveryScript) { s.receipt.fingerprint[0] ^= 1 }, ErrCreationMismatch},
		{"unsupported fingerprint version", func(s *recoveryScript) { s.receipt.fingerprintVersion = 2 }, ErrStored},
		{"short fingerprint", func(s *recoveryScript) { s.receipt.fingerprint = s.receipt.fingerprint[:31] }, ErrStored},
		{"wrong command", func(s *recoveryScript) { s.receipt.command = "enquiry.qualified" }, ErrStored},
		{"wrong expected version", func(s *recoveryScript) { s.receipt.expectedVersion = 1 }, ErrStored},
		{"enquiry ID present", func(s *recoveryScript) { s.receipt.enquiryID = text("partial-enquiry") }, ErrStored},
		{"event ID present", func(s *recoveryScript) { s.receipt.eventID = text("partial-event") }, ErrStored},
		{"resulting version present", func(s *recoveryScript) { s.receipt.resultingVersion = pgtype.Int8{Int64: 1, Valid: true} }, ErrStored},
		{"completion instant present", func(s *recoveryScript) { s.receipt.completedAt = stamp(created) }, ErrStored},
		{"joined event instant present", func(s *recoveryScript) { s.receipt.at = stamp(created) }, ErrStored},
		{"resource binding present", func(s *recoveryScript) { s.receipt.resourceMatches = true }, ErrStored},
		{"marked complete without bindings", func(s *recoveryScript) { s.receipt.completed = true }, ErrStored},
		{"expires after lookup", func(s *recoveryScript) { s.until = s.final }, authz.ErrUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s, _ := simulatedRecovery(t)
			// Decode the reservation before completion, with NULL completion and
			// join fields. The database does not allow this reservation to commit.
			s.receipt = creationReceipt{command: "enquiry.created", fingerprintVersion: 1, fingerprint: s.receipt.fingerprint}
			tc.edit(s)
			got, err := c.Recover(context.Background(), creationRequest, "original-key", captureInput())
			requireRecoveryFailure(t, got, err, tc.want)
		})
	}
}

func TestRecoveryRejectsInvalidConfigurationAndInput(t *testing.T) {
	var zero *FirstCreator
	got, err := zero.Recover(context.Background(), creationRequest, "original-key", captureInput())
	requireRecoveryFailure(t, got, err, ErrCreateConfiguration)
	c, s, _ := simulatedRecovery(t)
	got, err = c.Recover(context.Background(), creationRequest, "bad key", captureInput())
	requireRecoveryFailure(t, got, err, ErrSelector)
	if len(s.order) != 0 {
		t.Fatal("invalid key reached transaction queries")
	}
	input := captureInput()
	input.TravelEnd = ""
	got, err = c.Recover(context.Background(), creationRequest, "original-key", input)
	requireRecoveryFailure(t, got, err, enquiries.ErrInvalidInput)
	if !reflect.DeepEqual(s.order, []string{"fences", "identity", "facts", "clock"}) {
		t.Fatal("invalid input reached receipt lookup")
	}
}
