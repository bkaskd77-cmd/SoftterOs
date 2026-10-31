package postgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

func text(s string) pgtype.Text            { return pgtype.Text{String: s, Valid: true} }
func stamp(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }

var created = time.Date(2026, 10, 29, 12, 0, 0, 123456000, time.UTC)

func fixture(version int64) (storedEnquiry, []storedEvent) {
	r := storedEnquiry{
		OrganizationID: "org-2", ID: "enquiry-17", State: "New", CreatedBy: "creator-23", MembershipID: "creator-member-23",
		Input:   enquiries.Input{ContactName: "Synthetic Contact", ContactEmail: "contact@example.com", Destination: "Norway", TravellerCount: 3},
		Start:   pgtype.Date{Time: time.Date(2020, 2, 29, 0, 0, 0, 0, time.UTC), Valid: true},
		End:     pgtype.Date{Time: time.Date(2020, 3, 2, 0, 0, 0, 0, time.UTC), Valid: true},
		Created: stamp(created), Changed: stamp(created), Version: version, CreatorReference: true, AssigneeReference: true,
	}
	events := []storedEvent{{
		OrganizationID: r.OrganizationID, ActiveOrganizationID: r.OrganizationID, ID: "event-1", EnquiryID: r.ID, RequestKey: "request-1",
		ActorID: "creator-23", MembershipID: "creator-member-23", Action: "enquiry.created", Capability: "enquiries.create", Outcome: "success",
		ActorRevision: 7, OrganizationRevision: 11, NewState: "New", Version: 1, At: stamp(created),
		MemberReference: true, GrantReference: true, ReceiptReference: true,
	}}
	for v := int64(2); v <= version; v++ {
		e := storedEvent{
			OrganizationID: r.OrganizationID, ActiveOrganizationID: r.OrganizationID, ID: "event-2", EnquiryID: r.ID, RequestKey: "request-2",
			ActorID: "reviewer-41", MembershipID: "review-member-41", Grant: text("review-grant-41"),
			Action: "enquiry.review_started", Capability: "enquiries.review", Outcome: "success", ActorRevision: 13, OrganizationRevision: 17,
			PreviousState: text("New"), NewState: "Under review", Assignee: text("review-member-41"),
			PreviousVersion: pgtype.Int8{Int64: v - 1, Valid: true}, Version: v, At: stamp(created.Add(time.Duration(v-1) * time.Minute)),
			MemberReference: true, GrantReference: true, ReceiptReference: true,
		}
		if v == 3 {
			e.ID, e.RequestKey, e.Grant = "event-3", "request-3", text("qualify-grant-41")
			e.Action, e.Capability, e.PreviousState, e.NewState = "enquiry.qualified", "enquiries.qualify", text("Under review"), "Qualified"
			e.PreviousAssignee = e.Assignee
		}
		r.State, r.Assignee, r.Changed = e.NewState, e.Assignee, e.At
		events = append(events, e)
	}
	return r, events
}

func expected(version int64) enquiries.Snapshot {
	s := enquiries.Snapshot{
		ID: "enquiry-17", OrganizationID: "org-2", State: enquiries.StateNew,
		CreatedBy: "creator-23", MembershipID: "creator-member-23", CreatedAt: created, LastChangedAt: created, Version: uint64(version),
		Input: enquiries.Input{ContactName: "Synthetic Contact", ContactEmail: "contact@example.com", Destination: "Norway", TravellerCount: 3,
			TravelStart: "2020-02-29", TravelEnd: "2020-03-02"},
	}
	if version > 1 {
		s.State, s.AssigneeMembershipID, s.LastChangedAt = enquiries.StateUnderReview, "review-member-41", created.Add(time.Minute)
	}
	if version == 3 {
		s.State, s.LastChangedAt = enquiries.StateQualified, created.Add(2*time.Minute)
	}
	return s
}

func TestRestoreStoredStatesAndDetachedHistory(t *testing.T) {
	for version := int64(1); version <= 3; version++ {
		r, history := fixture(version)
		got, err := restore(r, history, "org-2", "enquiry-17")
		if err != nil || got.Enquiry.Snapshot() != expected(version) || len(got.Transitions) != int(version-1) {
			t.Fatalf("version %d lost independently expected state: %v", version, err)
		}
		wantCreation := enquiries.CreationAudit{Action: "enquiry.created", EnquiryID: "enquiry-17", OrganizationID: "org-2",
			ActorID: "creator-23", MembershipID: "creator-member-23", At: created, Capability: authz.CapabilityCreateEnquiry}
		if got.Enquiry.CreationAudit() != wantCreation {
			t.Fatal("historical creator changed")
		}
		for i, audit := range got.Transitions {
			want := enquiries.TransitionAudit{Action: "enquiry.review_started", OrganizationID: "org-2", ActiveOrganizationID: "org-2",
				EnquiryID: "enquiry-17", PreviousState: enquiries.StateNew, NewState: enquiries.StateUnderReview,
				ActorID: "reviewer-41", MembershipID: "review-member-41", GrantID: "review-grant-41", Capability: authz.CapabilityReviewEnquiry,
				AssigneeMembershipID: "review-member-41", PreviousVersion: 1, Version: 2, At: created.Add(time.Minute)}
			if i == 1 {
				want.Action, want.GrantID, want.Capability = "enquiry.qualified", "qualify-grant-41", authz.CapabilityQualifyEnquiry
				want.PreviousState, want.NewState, want.PreviousAssigneeMembershipID = enquiries.StateUnderReview, enquiries.StateQualified, "review-member-41"
				want.PreviousVersion, want.Version, want.At = 2, 3, created.Add(2*time.Minute)
			}
			if audit != want {
				t.Fatal("transition attribution or history changed")
			}
		}
		history[0].ActorID = "changed"
		r.Input.ContactName = "changed"
		if got.Enquiry.Snapshot() != expected(version) {
			t.Fatal("storage aliases domain state")
		}
		if version > 1 {
			got.Transitions[0].ActorID = "changed"
			if got.Enquiry.Snapshot() != expected(version) {
				t.Fatal("detached audit mutates domain state")
			}
		}
	}
}

func TestRestoreHistoricalReviewerAttribution(t *testing.T) {
	for _, reviewer := range []struct{ actor, membership string }{
		{"reviewer-41", "review-member-41"},
		{"reviewer-88", "review-member-88"},
	} {
		for _, version := range []int64{2, 3} {
			r, history := fixture(version)
			r.Assignee = text(reviewer.membership)
			for i := 1; i < len(history); i++ {
				history[i].ActorID, history[i].MembershipID = reviewer.actor, reviewer.membership
				history[i].Assignee = text(reviewer.membership)
				if i == 2 {
					history[i].PreviousAssignee = text(reviewer.membership)
				}
			}
			t.Run(reviewer.actor+"/"+r.State, func(t *testing.T) {
				got, err := restore(r, history, "org-2", "enquiry-17")
				want := expected(version)
				want.AssigneeMembershipID = reviewer.membership
				if err != nil || got.Enquiry.Snapshot() != want || len(got.Transitions) != int(version-1) {
					t.Fatal("valid historical reviewer fixture rejected or altered", err)
				}
				// Expected identities come from the independent case, not mapped output.
				review := got.Transitions[0]
				if review.Action != "enquiry.review_started" || review.ActorID != reviewer.actor ||
					review.MembershipID != reviewer.membership || review.AssigneeMembershipID != reviewer.membership ||
					review.PreviousAssigneeMembershipID != "" {
					t.Fatal("review actor or membership attribution lost")
				}
				if version == 3 {
					qualification := got.Transitions[1]
					if qualification.Action != "enquiry.qualified" || qualification.ActorID != reviewer.actor ||
						qualification.MembershipID != reviewer.membership || qualification.AssigneeMembershipID != reviewer.membership ||
						qualification.PreviousAssigneeMembershipID != reviewer.membership {
						t.Fatal("qualification actor or membership attribution lost")
					}
				}
			})
		}
	}
}

func TestRejectInvalidStoredMapping(t *testing.T) {
	cases := map[string]func(*storedEnquiry, *[]storedEvent){
		"wrong owner":            func(r *storedEnquiry, _ *[]storedEvent) { r.OrganizationID = "org-1" },
		"wrong selector":         func(r *storedEnquiry, _ *[]storedEvent) { r.ID = "other" },
		"invalid creator":        func(r *storedEnquiry, _ *[]storedEvent) { r.CreatedBy = "bad actor" },
		"invalid member":         func(r *storedEnquiry, _ *[]storedEvent) { r.MembershipID = "" },
		"invalid input":          func(r *storedEnquiry, _ *[]storedEvent) { r.Input.ContactName = " untrimmed" },
		"invalid email":          func(r *storedEnquiry, _ *[]storedEvent) { r.Input.ContactEmail = "private-invalid" },
		"invalid count":          func(r *storedEnquiry, _ *[]storedEvent) { r.Input.TravellerCount = 100 },
		"unknown state":          func(r *storedEnquiry, _ *[]storedEvent) { r.State = "Drafting" },
		"negative version":       func(r *storedEnquiry, _ *[]storedEvent) { r.Version = -1 },
		"zero version":           func(r *storedEnquiry, _ *[]storedEvent) { r.Version = 0 },
		"large version":          func(r *storedEnquiry, _ *[]storedEvent) { r.Version = 1 << 62 },
		"state version":          func(r *storedEnquiry, _ *[]storedEvent) { r.State = "New" },
		"null assignee":          func(r *storedEnquiry, _ *[]storedEvent) { r.Assignee = pgtype.Text{} },
		"empty assignee":         func(r *storedEnquiry, _ *[]storedEvent) { r.Assignee = text("") },
		"hidden assignee":        func(r *storedEnquiry, _ *[]storedEvent) { r.Assignee.Valid = false },
		"creator reference":      func(r *storedEnquiry, _ *[]storedEvent) { r.CreatorReference = false },
		"assignee reference":     func(r *storedEnquiry, _ *[]storedEvent) { r.AssigneeReference = false },
		"partial dates":          func(r *storedEnquiry, _ *[]storedEvent) { r.Start = pgtype.Date{} },
		"reversed dates":         func(r *storedEnquiry, _ *[]storedEvent) { r.Start, r.End = r.End, r.Start },
		"infinite date":          func(r *storedEnquiry, _ *[]storedEvent) { r.End.InfinityModifier = pgtype.Infinity },
		"date time":              func(r *storedEnquiry, _ *[]storedEvent) { r.Start.Time = r.Start.Time.Add(time.Hour) },
		"date range":             func(r *storedEnquiry, _ *[]storedEvent) { r.End.Time = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		"null time":              func(r *storedEnquiry, _ *[]storedEvent) { r.Created.Valid = false },
		"infinite time":          func(r *storedEnquiry, _ *[]storedEvent) { r.Created.InfinityModifier = pgtype.NegativeInfinity },
		"nanosecond time":        func(r *storedEnquiry, _ *[]storedEvent) { r.Created.Time = r.Created.Time.Add(time.Nanosecond) },
		"zero time":              func(r *storedEnquiry, _ *[]storedEvent) { r.Created.Time = time.Time{} },
		"changed before created": func(r *storedEnquiry, _ *[]storedEvent) { r.Changed.Time = created.Add(-time.Microsecond) },
		"missing history":        func(_ *storedEnquiry, h *[]storedEvent) { *h = nil },
		"incomplete history":     func(_ *storedEnquiry, h *[]storedEvent) { *h = (*h)[:2] },
		"extra history":          func(_ *storedEnquiry, h *[]storedEvent) { *h = append(*h, (*h)[2]) },
		"unordered history":      func(_ *storedEnquiry, h *[]storedEvent) { (*h)[0], (*h)[1] = (*h)[1], (*h)[0] },
		"creation actor":         func(_ *storedEnquiry, h *[]storedEvent) { (*h)[0].ActorID = "another" },
		"creation member":        func(_ *storedEnquiry, h *[]storedEvent) { (*h)[0].MembershipID = "another" },
		"creation time":          func(_ *storedEnquiry, h *[]storedEvent) { (*h)[0].At.Time = created.Add(time.Microsecond) },
		"creation prior":         func(_ *storedEnquiry, h *[]storedEvent) { (*h)[0].PreviousVersion = pgtype.Int8{Valid: true} },
		"creation grant":         func(_ *storedEnquiry, h *[]storedEvent) { (*h)[0].Grant = text("grant") },
		"event owner":            func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].OrganizationID = "org-1" },
		"event resource":         func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].EnquiryID = "another" },
		"active org":             func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].ActiveOrganizationID = "org-1" },
		"event id":               func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].ID = "bad id" },
		"duplicate event":        func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].ID = (*h)[0].ID },
		"duplicate request":      func(_ *storedEnquiry, h *[]storedEvent) { (*h)[2].RequestKey = (*h)[1].RequestKey },
		"failed outcome":         func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].Outcome = "failure" },
		"revision":               func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].ActorRevision = 0 },
		"membership reference":   func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].MemberReference = false },
		"grant reference":        func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].GrantReference = false },
		"receipt reference":      func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].ReceiptReference = false },
		"wrong action":           func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].Action = "enquiry.qualified" },
		"wrong capability":       func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].Capability = "enquiries.qualify" },
		"missing grant":          func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].Grant = pgtype.Text{} },
		"wrong prior state":      func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].PreviousState = text("Qualified") },
		"wrong prior version":    func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].PreviousVersion.Int64 = 0 },
		"review reassigned":      func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].PreviousAssignee = text("old") },
		"non assignee":           func(_ *storedEnquiry, h *[]storedEvent) { (*h)[2].MembershipID = "another" },
		"changed assignee":       func(_ *storedEnquiry, h *[]storedEvent) { (*h)[2].PreviousAssignee = text("another") },
		"backward event time":    func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].At.Time = created.Add(-time.Microsecond) },
		"nanosecond event":       func(_ *storedEnquiry, h *[]storedEvent) { (*h)[1].At.Time = created.Add(time.Nanosecond) },
		"last state":             func(_ *storedEnquiry, h *[]storedEvent) { (*h)[2].NewState = "New" },
		"last time":              func(_ *storedEnquiry, h *[]storedEvent) { (*h)[2].At.Time = created.Add(3 * time.Minute) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r, h := fixture(3)
			mutate(&r, &h)
			got, err := restore(r, h, "org-2", "enquiry-17")
			if err != ErrStored || err.Error() != "invalid stored enquiry" || !reflect.DeepEqual(got, Loaded{}) {
				t.Fatal("corruption returned a partial value or unsafe error")
			}
		})
	}
}

func TestTimestampAndCalendarBoundaries(t *testing.T) {
	for _, at := range []time.Time{time.Date(1, 1, 1, 0, 0, 0, 1000, time.UTC), time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC), created.In(time.FixedZone("offset", -7*3600))} {
		r, h := fixture(1)
		r.Created, r.Changed, h[0].At = stamp(at), stamp(at), stamp(at)
		r.Start, r.End = pgtype.Date{}, pgtype.Date{}
		got, err := restore(r, h, "org-2", "enquiry-17")
		if err != nil || !got.Enquiry.CreatedAt().Equal(at) || got.Enquiry.CreatedAt().Nanosecond() != at.Nanosecond() || got.Enquiry.Input().TravelStart != "" {
			t.Fatal("representable instant changed", err)
		}
	}
	for _, at := range []time.Time{time.Time{}, time.Date(0, 12, 31, 23, 59, 59, 0, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), created.Add(time.Nanosecond)} {
		if instant(stamp(at)) {
			t.Fatal("unsupported instant accepted")
		}
	}
	for _, date := range []string{"0001-01-01", "9999-12-31", "2020-02-29"} {
		d, _ := time.Parse("2006-01-02", date)
		got, ok := calendar(pgtype.Date{Time: d.In(time.UTC), Valid: true})
		if !ok || got != date {
			t.Fatal("calendar date changed")
		}
	}
	// Offset calendar midnight must not be shifted to a different UTC date.
	d := pgtype.Date{Time: time.Date(2020, 2, 29, 0, 0, 0, 0, time.FixedZone("calendar", 14*3600)), Valid: true}
	if got, ok := calendar(d); !ok || got != "2020-02-29" {
		t.Fatal("calendar treated as instant")
	}
}

type queryFailure struct{ calls int }

func (*queryFailure) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("unexpected exec")
}
func (*queryFailure) QueryRow(context.Context, string, ...any) pgx.Row { panic("unexpected QueryRow") }
func (q *queryFailure) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	q.calls++
	if sql != loadSQL || !reflect.DeepEqual(args, []any{"org-2", "enquiry-17"}) {
		panic("unbound selector")
	}
	return nil, errors.New("private driver details")
}

func TestSelectorsAndSafeQueryFailure(t *testing.T) {
	q := &queryFailure{}
	for _, id := range []string{"", "bad id", "id' OR true", strings.Repeat("a", 129)} {
		if got, err := Load(context.Background(), q, "org-2", id); err != ErrSelector || !reflect.DeepEqual(got, Loaded{}) {
			t.Fatal("invalid selector accepted")
		}
		if _, err := Load(context.Background(), q, id, "enquiry-17"); err != ErrSelector {
			t.Fatal("invalid org accepted")
		}
	}
	if q.calls != 0 {
		t.Fatal("invalid selector queried storage")
	}
	if got, err := Load(context.Background(), q, "org-2", "enquiry-17"); err != ErrStorage || !reflect.DeepEqual(got, Loaded{}) || q.calls != 1 {
		t.Fatal("unsafe query failure")
	}
}

// These rows supply typed columns to the real Load/Scan/Err/Close path. They do
// not construct a domain value, replace Load, or rely on a database fault race.
type iterationRows struct {
	pgx.Rows
	values          [][]any
	position, scans int
	failure         error
	closed          bool
}

func (r *iterationRows) Next() bool {
	if r.position == len(r.values) {
		return false
	}
	r.position++
	return true
}

func (r *iterationRows) Scan(dest ...any) error {
	values := r.values[r.position-1]
	if len(dest) != len(values) {
		panic("iteration fixture column count mismatch")
	}
	for i, value := range values {
		switch target := dest[i].(type) {
		case *string:
			*target = value.(string)
		case *int:
			*target = value.(int)
		case *int64:
			*target = value.(int64)
		case *bool:
			*target = value.(bool)
		case *pgtype.Date:
			*target = value.(pgtype.Date)
		case *pgtype.Timestamptz:
			*target = value.(pgtype.Timestamptz)
		case *pgtype.Text:
			*target = value.(pgtype.Text)
		case *pgtype.Int8:
			*target = value.(pgtype.Int8)
		default:
			panic("unexpected iteration fixture scan target")
		}
	}
	r.scans++
	return nil
}

func (r *iterationRows) Err() error { return r.failure }
func (r *iterationRows) Close()     { r.closed = true }

type iterationExecutor struct {
	rows  *iterationRows
	calls int
}

func (*iterationExecutor) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("unexpected exec")
}
func (*iterationExecutor) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("unexpected QueryRow")
}
func (q *iterationExecutor) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	if sql != loadSQL || !reflect.DeepEqual(args, []any{"org-2", "enquiry-17"}) {
		panic("iteration fixture query/selector mismatch")
	}
	q.calls++
	return q.rows, nil
}

func iterationValues(r storedEnquiry, history []storedEvent) [][]any {
	var values [][]any
	for _, event := range history {
		values = append(values, []any{
			r.OrganizationID, r.ID, r.Input.ContactName, r.Input.ContactEmail,
			r.Input.Destination, r.Input.TravellerCount, r.Start, r.End,
			r.State, r.CreatedBy, r.MembershipID, r.Created,
			r.Assignee, r.Version, r.Changed, r.CreatorReference, r.AssigneeReference,
			event.OrganizationID, event.ID, event.EnquiryID, event.RequestKey, event.ActiveOrganizationID,
			event.ActorID, event.MembershipID, event.Grant, event.Action, event.Capability, event.Outcome,
			event.ActorRevision, event.OrganizationRevision, event.PreviousState, event.NewState,
			event.PreviousAssignee, event.Assignee, event.PreviousVersion, event.Version, event.At,
			event.MemberReference, event.GrantReference, event.ReceiptReference,
		})
	}
	return values
}

func TestLoadIterationErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		version  int64
		rowCount int
	}{
		{"before-first-row", 1, 0},
		{"after-valid-new-row", 1, 1},
		{"after-complete-qualified-history", 3, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, history := fixture(tc.version)
			values := iterationValues(r, history)[:tc.rowCount]
			// The identical rows must succeed without the injected iteration error.
			positive := &iterationRows{values: values}
			positiveQuery := &iterationExecutor{rows: positive}
			got, err := Load(context.Background(), positiveQuery, "org-2", "enquiry-17")
			if tc.rowCount == 0 {
				if err != ErrNotFound || !reflect.DeepEqual(got, Loaded{}) {
					t.Fatal("empty-result positive control failed", err)
				}
			} else if err != nil || got.Enquiry.Snapshot() != expected(tc.version) || len(got.Transitions) != int(tc.version-1) {
				t.Fatal("valid-row positive control failed", err)
			}
			if !positive.closed || positive.scans != tc.rowCount || positiveQuery.calls != 1 {
				t.Fatal("positive control did not consume and close the intended rows")
			}
			for _, failure := range []struct {
				name string
				err  error
			}{
				{"connection", errors.New("private driver failure")},
				{"canceled", context.Canceled},
				{"deadline", context.DeadlineExceeded},
			} {
				t.Run(failure.name, func(t *testing.T) {
					rows := &iterationRows{values: values, failure: failure.err}
					query := &iterationExecutor{rows: rows}
					got, err := Load(context.Background(), query, "org-2", "enquiry-17")
					if err != ErrStorage {
						t.Fatalf("iteration failure must return ErrStorage; got %v", err)
					}
					if !reflect.DeepEqual(got, Loaded{}) {
						t.Fatal("iteration failure returned an enquiry or partial audit result")
					}
					if !rows.closed || rows.scans != tc.rowCount || query.calls != 1 {
						t.Fatal("iteration failure did not consume and close the intended rows")
					}
				})
			}
		})
	}
}
