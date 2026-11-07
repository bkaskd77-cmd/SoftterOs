package postgres

import (
	"context"
	"crypto/rand"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

// Simulation of completion classification, not a real lost commit acknowledgement.
// The unchanged transaction package separately tests real backend failures.
type simulatedCreationBoundary struct {
	tx          *creationCommands
	commitError error
	calls       int
}

func (b *simulatedCreationBoundary) WithTx(ctx context.Context, s pg.Scope, fn func(context.Context, pg.Executor) error) error {
	b.calls++
	if s != (pg.Scope{ActorID: "actor-17", OrganizationID: "org-29"}) {
		panic("wrong scope")
	}
	if err := fn(ctx, b.tx); err != nil {
		return err
	}
	return b.commitError
}

type creationCommands struct {
	*creationScript
	duplicate bool
	fail      string
	args      map[string][]any
}

func (s *creationCommands) Exec(_ context.Context, q string, args ...any) (pgconn.CommandTag, error) {
	s.args[q] = append([]any(nil), args...)
	name := ""
	switch q {
	case reserveCreationSQL:
		name = "reserve"
	case insertCreationSQL:
		name = "enquiry"
	case insertCreationEventSQL:
		name = "event"
	case completeCreationSQL:
		name = "complete"
	case creationIntegritySQL:
		name = "integrity"
	default:
		panic("unexpected write")
	}
	s.order = append(s.order, name)
	if s.fail == name {
		return pgconn.CommandTag{}, errors.New("private SQL details")
	}
	if name == "reserve" && s.duplicate {
		return pgconn.NewCommandTag("INSERT 0 0"), nil
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}
func simulatedCreator(t *testing.T) (*FirstCreator, *simulatedCreationBoundary, *int) {
	t.Helper()
	s := &creationCommands{creationScript: script(), args: map[string][]any{}}
	b := &simulatedCreationBoundary{tx: s}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	calls := 0
	c, err := NewFirstCreator(&pg.DB{}, scriptedIdentity(s.creationScript), key[:], func() (string, error) { calls++; return "generated-" + strconv.Itoa(calls), nil })
	if err != nil {
		t.Fatal(err)
	}
	c.authority.db = b
	return c, b, &calls
}

func TestFirstCreationSimulatedOrderingAndBindings(t *testing.T) {
	c, b, ids := simulatedCreator(t)
	got, err := c.Create(context.Background(), creationRequest, "key-59", captureInput())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"fences", "identity", "facts", "clock", "reserve", "clock", "enquiry", "event", "clock", "complete", "integrity", "clock"}
	if !reflect.DeepEqual(b.tx.order, want) || b.calls != 1 || *ids != 2 {
		t.Fatal("same-transaction order violated", b.tx.order)
	}
	if got.Enquiry.CreatedBy() != "actor-17" || got.Audit.MembershipID != "member-31" || got.EventID != "generated-2" || got.Enquiry.Input() != captureInput() {
		t.Fatal("invalid candidate")
	}
	reservation := b.tx.args[reserveCreationSQL]
	if !reflect.DeepEqual(reservation[:4], []any{"org-29", "member-31", "key-59", "actor-17"}) {
		t.Fatal("unverified receipt binding")
	}
	event := b.tx.args[insertCreationEventSQL]
	if !reflect.DeepEqual(event[:10], []any{"org-29", "generated-2", "generated-1", "key-59", "actor-17", "member-31", "enquiry.created", "enquiries.create", int64(7), int64(9)}) {
		t.Fatal("event attribution/revisions differ")
	}
	completion := b.tx.args[completeCreationSQL]
	if !reflect.DeepEqual(completion[:7], []any{"org-29", "member-31", "key-59", "actor-17", reservation[4], "generated-1", "generated-2"}) {
		t.Fatal("receipt completion binding differs")
	}
}

func TestFirstCreationSimulatedOutcomeClassification(t *testing.T) {
	for _, outcome := range []error{pg.ErrCommitRejected, pg.ErrCommitUnknown, errors.Join(context.Canceled, pg.ErrCleanup)} {
		c, b, _ := simulatedCreator(t)
		b.commitError = outcome
		got, err := c.Create(context.Background(), creationRequest, "key-59", captureInput())
		if err != outcome || !reflect.DeepEqual(got, Created{}) || b.calls != 1 {
			t.Fatal("outcome lost, result escaped, or retry occurred", err)
		}
	}
	for _, name := range []string{"reserve", "enquiry", "event", "complete", "integrity"} {
		t.Run(name, func(t *testing.T) {
			c, b, _ := simulatedCreator(t)
			b.tx.fail = name
			got, err := c.Create(context.Background(), creationRequest, "key-59", captureInput())
			if !errors.Is(err, ErrStorage) || err.Error() != ErrStorage.Error() || !reflect.DeepEqual(got, Created{}) || b.calls != 1 {
				t.Fatal("unsafe write failure", err)
			}
		})
	}
}

func TestFirstCreationDenialBeforeSideEffects(t *testing.T) {
	c, b, ids := simulatedCreator(t)
	b.tx.active = false
	got, err := c.Create(context.Background(), creationRequest, "key-59", enquiries.Input{})
	if !errors.Is(err, authz.ErrUnauthorized) || *ids != 0 || len(b.tx.args) != 0 || !reflect.DeepEqual(got, Created{}) {
		t.Fatal("authorization did not precede side effects")
	}
	c, b, ids = simulatedCreator(t)
	got, err = c.Create(context.Background(), creationRequest, "key-59", enquiries.Input{})
	if !errors.Is(err, enquiries.ErrInvalidInput) || *ids != 0 || len(b.tx.args) != 0 || !reflect.DeepEqual(got, Created{}) {
		t.Fatal("input validation did not precede side effects")
	}
	c, b, ids = simulatedCreator(t)
	b.tx.duplicate = true
	got, err = c.Create(context.Background(), creationRequest, "key-59", captureInput())
	if err != ErrDuplicateCreation || *ids != 0 || len(b.tx.args) != 1 || !reflect.DeepEqual(got, Created{}) {
		t.Fatal("duplicate made business writes")
	}
}

func TestFirstCreationSimulatedExcludedFieldsStayOutOfReceiptFingerprint(t *testing.T) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	var previousFingerprint []byte
	var previous Created
	for i := 0; i < 2; i++ {
		c, b, _ := simulatedCreator(t)
		c.secret = secret
		r := creationRequest
		r.RequestID = "attestation-" + strconv.Itoa(i)
		c.authority.identity = identityFunc(func(_ context.Context, request CreationIdentityRequest) (CreationAttestation, error) {
			if request.ActorID != "actor-17" || request.RequestID != r.RequestID {
				t.Fatal("wrong attestation request")
			}
			b.tx.order = append(b.tx.order, "identity")
			return CreationAttestation{Actor: authz.Actor{ID: "actor-17", Authenticated: true}, RequestID: r.RequestID}, nil
		})
		b.tx.action = stamp(created.Add(time.Duration(i) * time.Minute))
		b.tx.final = stamp(b.tx.action.Time.Add(time.Microsecond))
		ids := 0
		c.newID = func() (string, error) { ids++; return "attempt-" + strconv.Itoa(i) + "-id-" + strconv.Itoa(ids), nil }
		got, err := c.Create(context.Background(), r, "key-59", captureInput())
		if err != nil {
			t.Fatal(err)
		}
		fingerprint := b.tx.args[reserveCreationSQL][4].([]byte)
		if i > 0 && (!reflect.DeepEqual(fingerprint, previousFingerprint) || got.EventID == previous.EventID || got.Enquiry.ID() == previous.Enquiry.ID() || got.Audit.At.Equal(previous.Audit.At)) {
			t.Fatal("excluded generated IDs, attestation ID or timestamps changed the fingerprint, or positive controls did not vary")
		}
		previousFingerprint = append([]byte(nil), fingerprint...)
		previous = got
	}
}
