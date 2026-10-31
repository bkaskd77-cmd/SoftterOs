package postgres

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
)

// Only the reviewed disposable harness supplies these targets. Administrative
// seeding and test-only LOCAL ROLE switching are not runtime authentication.
func database(t *testing.T) (*pg.DB, *pgx.Conn, string) {
	t.Helper()
	if os.Getenv("SOFTTEROS_PG_INTEGRATION") != "1" {
		t.Skip("run scripts/test-postgres-go.py")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := pg.DefaultConfig(os.Getenv("SOFTTEROS_TEST_SOCKET"), 5432, os.Getenv("SOFTTEROS_TEST_DATABASE"), os.Getenv("USER"))
	cfg.MaxConns = 1
	db, err := pg.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	cc, err := pgx.ParseConfig("")
	if err != nil {
		t.Fatal("fixture configuration")
	}
	cc.Host, cc.Port, cc.Database, cc.User, cc.Password = cfg.Host, cfg.Port, cfg.Database, cfg.User, ""
	cc.TLSConfig, cc.Fallbacks = nil, nil
	cc.ConnectTimeout = 5 * time.Second
	cc.RuntimeParams = map[string]string{"timezone": "UTC", "statement_timeout": "10000", "lock_timeout": "500", "transaction_timeout": "20000"}
	admin, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		t.Fatal("fixture connection")
	}
	t.Cleanup(func() {
		c, end := context.WithTimeout(context.Background(), 3*time.Second)
		defer end()
		if err := admin.Close(c); err != nil {
			t.Error("fixture close")
		}
	})
	role := os.Getenv("SOFTTEROS_TEST_RUNTIME")
	if !identifier(role) {
		t.Fatal("missing restricted role")
	}
	return db, admin, role
}

func restricted(ctx context.Context, tx pg.Executor, role string) error {
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
		return err
	}
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT current_user=$1 AND NOT rolsuper AND NOT rolbypassrls
 AND NOT rolcreatedb AND NOT rolcreaterole FROM pg_roles WHERE rolname=current_user`, role).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return errors.New("unrestricted fixture query")
	}
	return nil
}

func insertEvent(ctx context.Context, tx pgx.Tx, e storedEvent) error {
	_, err := tx.Exec(ctx, `INSERT INTO softteros_enquiries.enquiry_command_receipts
 (organization_id,membership_id,request_key,actor_id,command,expected_version,fingerprint_version,fingerprint,
 enquiry_id,event_id,resulting_version,completed,completed_at)
 VALUES($1,$2,$3,$4,$5,$6,1,decode(repeat('ab',32),'hex'),$7,$8,$9,true,$10)`,
		e.OrganizationID, e.MembershipID, e.RequestKey, e.ActorID, e.Action, e.Version-1, e.EnquiryID, e.ID, e.Version, e.At)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO softteros_enquiries.enquiry_events
 (organization_id,event_id,enquiry_id,request_key,active_organization_id,actor_id,membership_id,grant_id,
 action,capability,outcome,actor_authority_revision,organization_authority_revision,previous_state,new_state,
 previous_assignee_membership_id,assignee_membership_id,previous_version,resulting_version,at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
		e.OrganizationID, e.ID, e.EnquiryID, e.RequestKey, e.ActiveOrganizationID, e.ActorID, e.MembershipID, e.Grant,
		e.Action, e.Capability, e.Outcome, e.ActorRevision, e.OrganizationRevision, e.PreviousState, e.NewState,
		e.PreviousAssignee, e.Assignee, e.PreviousVersion, e.Version, e.At)
	return err
}

func advance(ctx context.Context, tx pgx.Tx, e storedEvent) error {
	_, err := tx.Exec(ctx, `INSERT INTO softteros_access.enquiry_transition_grants VALUES
 ($1,$2,$3,$4,$5,$6,false,true,'2000-01-01+00','9999-01-01+00')`,
		e.OrganizationID, e.Grant, e.ActorID, e.MembershipID, e.EnquiryID, e.Capability)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE softteros_enquiries.enquiries SET state=$3,version=$4,
 assignee_membership_id=$5,last_changed_at=$6 WHERE organization_id=$1 AND enquiry_id=$2`,
		e.OrganizationID, e.EnquiryID, e.NewState, e.Version, e.Assignee, e.At)
	if err != nil {
		return err
	}
	return insertEvent(ctx, tx, e)
}

func seed(t *testing.T, admin *pgx.Conn, r storedEnquiry, events []storedEvent) {
	t.Helper()
	ctx, end := context.WithTimeout(context.Background(), 10*time.Second)
	defer end()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(c)
	}()
	// Historical bindings deliberately remain after ordinary offboarding.
	bindings := append([]storedEvent(nil), events...)
	bindings = append(bindings, storedEvent{OrganizationID: r.OrganizationID, ActorID: "reviewer-41", MembershipID: "review-member-41"})
	for _, e := range bindings {
		if _, err = tx.Exec(ctx, "INSERT INTO softteros_access.actors VALUES($1) ON CONFLICT DO NOTHING", e.ActorID); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO softteros_access.memberships VALUES
 ($1,$2,$3,false,true,'2000-01-01+00','9999-01-01+00') ON CONFLICT DO NOTHING`, e.OrganizationID, e.MembershipID, e.ActorID); err != nil {
			t.Fatal(err)
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO softteros_enquiries.enquiries VALUES
 ($1,$2,$3,$4,$5,$6,$7,$8,'New',$9,$10,$11,NULL,1,$11)`, r.OrganizationID, r.ID,
		r.Input.ContactName, r.Input.ContactEmail, r.Input.Destination, r.Input.TravellerCount, r.Start, r.End, r.CreatedBy, r.MembershipID, r.Created)
	if err != nil {
		t.Fatal(err)
	}
	if err = insertEvent(ctx, tx, events[0]); err != nil {
		t.Fatal(err)
	}
	for _, e := range events[1:] {
		if err = advance(ctx, tx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal("fixture did not satisfy real commit integrity", err)
	}
}

// Unique resource/event/request IDs within the disposable database; both tenants
// intentionally use the same local enquiry IDs. No catalog objects are added.
func namedFixture(version int64, suffix, org string) (storedEnquiry, []storedEvent) {
	r, h := fixture(version)
	r.OrganizationID, r.ID = org, "load-"+suffix
	for i := range h {
		h[i].OrganizationID, h[i].ActiveOrganizationID, h[i].EnquiryID = org, org, r.ID
		h[i].ID = "load-event-" + suffix + "-" + string(rune('1'+i))
		h[i].RequestKey = "load-request-" + suffix + "-" + string(rune('1'+i))
		if h[i].Grant.Valid {
			h[i].Grant.String += "-" + suffix
		}
	}
	return r, h
}

func TestIntegrationLoadStatesAndIsolation(t *testing.T) {
	db, admin, role := database(t)
	for v := int64(1); v <= 3; v++ {
		suffix := string(rune('0' + v))
		for _, org := range []string{"org-1", "org-2"} {
			r, h := namedFixture(v, suffix, org)
			if org == "org-1" {
				r.Input.Destination = "Iceland"
				r.CreatedBy, r.MembershipID = "creator-99", "creator-member-99"
				h[0].ActorID, h[0].MembershipID = r.CreatedBy, r.MembershipID
			}
			seed(t, admin, r, h)
			var got Loaded
			err := db.WithTx(context.Background(), pg.Scope{OrganizationID: org, ActorID: "actor-1"}, func(ctx context.Context, tx pg.Executor) error {
				if err := restricted(ctx, tx, role); err != nil {
					return err
				}
				var err error
				got, err = Load(ctx, tx, org, r.ID)
				return err
			})
			want := expected(v)
			want.ID, want.OrganizationID = r.ID, org
			if org == "org-1" {
				want.Input.Destination = "Iceland"
				want.CreatedBy, want.MembershipID = "creator-99", "creator-member-99"
			}
			if err != nil || got.Enquiry.Snapshot() != want || len(got.Transitions) != int(v-1) {
				t.Fatal("stored state/history/tenant mapping", org, v, err)
			}
			for i, a := range got.Transitions {
				if a.ActorID != "reviewer-41" || a.MembershipID != "review-member-41" || a.OrganizationID != org ||
					a.EnquiryID != r.ID || a.Version != uint64(i+2) || a.GrantID != h[i+1].Grant.String || !a.At.Equal(created.Add(time.Duration(i+1)*time.Minute)) {
					t.Fatal("lost transition evidence")
				}
			}
		}
	}
	// A real row exists only in org-2. Missing and inaccessible selectors match.
	r, h := namedFixture(1, "private", "org-2")
	seed(t, admin, r, h)
	for _, tc := range []struct{ active, requested, id string }{
		{"org-1", "org-1", "missing"}, {"org-1", "org-1", r.ID}, {"org-1", "org-2", r.ID},
		{"org-2", "org-1", "load-1"}, {"unknown-org", "unknown-org", "load-1"},
	} {
		err := db.WithTx(context.Background(), pg.Scope{OrganizationID: tc.active, ActorID: "actor-1"}, func(ctx context.Context, tx pg.Executor) error {
			if err := restricted(ctx, tx, role); err != nil {
				return err
			}
			got, err := Load(ctx, tx, tc.requested, tc.id)
			if !reflect.DeepEqual(got, Loaded{}) {
				t.Fatal("partial inaccessible result")
			}
			return err
		})
		if err != ErrNotFound {
			t.Fatal("missing/inaccessible difference", err)
		}
	}
	// Explicitly exercise RLS when the query has no organization predicate.
	if err := db.WithTx(context.Background(), pg.Scope{OrganizationID: "org-1", ActorID: "actor-1"}, func(ctx context.Context, tx pg.Executor) error {
		if err := restricted(ctx, tx, role); err != nil {
			return err
		}
		var n int
		var tenantOnly bool
		if err := tx.QueryRow(ctx, "SELECT count(*),bool_and(organization_id='org-1') FROM softteros_enquiries.enquiries").Scan(&n, &tenantOnly); err != nil {
			return err
		}
		if n < 3 || !tenantOnly {
			t.Fatal("RLS exposed foreign tenant")
		}
		if _, err := tx.Exec(ctx, "SELECT set_config('softteros.organization_id','',true)"); err != nil {
			return err
		}
		got, err := Load(ctx, tx, "org-1", "load-1")
		if err != ErrNotFound || !reflect.DeepEqual(got, Loaded{}) {
			t.Fatal("missing context exposed data")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationLoadHistoricalReviewerAttribution(t *testing.T) {
	db, admin, role := database(t)
	for _, reviewer := range []struct{ actor, membership, organization, suffix string }{
		{"reviewer-41", "review-member-41", "org-1", "reviewer-41"},
		{"reviewer-88", "review-member-88", "org-2", "reviewer-88"},
	} {
		for _, version := range []int64{2, 3} {
			suffix := reviewer.suffix + "-" + string(rune('0'+version))
			r, history := namedFixture(version, suffix, reviewer.organization)
			r.Assignee = text(reviewer.membership)
			for i := 1; i < len(history); i++ {
				history[i].ActorID, history[i].MembershipID = reviewer.actor, reviewer.membership
				history[i].Assignee = text(reviewer.membership)
				if i == 2 {
					history[i].PreviousAssignee = text(reviewer.membership)
				}
			}
			t.Run(reviewer.actor+"/"+r.State, func(t *testing.T) {
				// Commits must satisfy the unchanged attribution/assignment constraints.
				seed(t, admin, r, history)
				var got Loaded
				err := db.WithTx(context.Background(), pg.Scope{OrganizationID: reviewer.organization, ActorID: "actor-1"}, func(ctx context.Context, tx pg.Executor) error {
					if err := restricted(ctx, tx, role); err != nil {
						return err
					}
					var err error
					got, err = Load(ctx, tx, reviewer.organization, "load-"+suffix)
					return err
				})
				want := expected(version)
				want.ID, want.OrganizationID, want.AssigneeMembershipID = "load-"+suffix, reviewer.organization, reviewer.membership
				if err != nil || got.Enquiry.Snapshot() != want || len(got.Transitions) != int(version-1) {
					t.Fatal("valid historical reviewer load rejected or altered", err)
				}
				review := got.Transitions[0]
				if review.Action != "enquiry.review_started" || review.ActorID != reviewer.actor ||
					review.MembershipID != reviewer.membership || review.OrganizationID != reviewer.organization ||
					review.AssigneeMembershipID != reviewer.membership || review.PreviousAssigneeMembershipID != "" {
					t.Fatal("loaded review actor or membership attribution lost")
				}
				if version == 3 {
					qualification := got.Transitions[1]
					if qualification.Action != "enquiry.qualified" || qualification.ActorID != reviewer.actor ||
						qualification.MembershipID != reviewer.membership || qualification.OrganizationID != reviewer.organization ||
						qualification.AssigneeMembershipID != reviewer.membership || qualification.PreviousAssigneeMembershipID != reviewer.membership {
						t.Fatal("loaded qualification actor or membership attribution lost")
					}
				}
			})
		}
	}
}

type afterQuery struct {
	pg.Executor
	calls int
	after func()
}

func (q *afterQuery) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	q.calls++
	rows, err := q.Executor.Query(ctx, sql, args...)
	if err == nil {
		q.after()
	}
	return rows, err
}

func TestIntegrationLoadSingleSnapshot(t *testing.T) {
	db, admin, role := database(t)
	r, h := namedFixture(1, "concurrent", "org-2")
	seed(t, admin, r, h)
	_, future := namedFixture(2, "concurrent", "org-2")
	var got Loaded
	err := db.WithTx(context.Background(), pg.Scope{OrganizationID: "org-2", ActorID: "actor-1"}, func(ctx context.Context, tx pg.Executor) error {
		if err := restricted(ctx, tx, role); err != nil {
			return err
		}
		q := &afterQuery{Executor: tx, after: func() {
			c, end := context.WithTimeout(context.Background(), 5*time.Second)
			defer end()
			writer, err := admin.Begin(c)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_ = writer.Rollback(cleanup)
			}()
			if err = advance(c, writer, future[1]); err != nil {
				t.Fatal(err)
			}
			if err = writer.Commit(c); err != nil {
				t.Fatal("concurrent positive control", err)
			}
		}}
		var err error
		got, err = Load(ctx, q, "org-2", r.ID)
		if q.calls != 1 {
			t.Fatal("split READ COMMITTED reads")
		}
		return err
	})
	if err != nil || got.Enquiry.State() != enquiries.StateNew || got.Enquiry.Version() != 1 || len(got.Transitions) != 0 {
		t.Fatal("mixed statement snapshots", err)
	}
	err = db.WithTx(context.Background(), pg.Scope{OrganizationID: "org-2", ActorID: "actor-1"}, func(ctx context.Context, tx pg.Executor) error {
		if err := restricted(ctx, tx, role); err != nil {
			return err
		}
		var err error
		got, err = Load(ctx, tx, "org-2", r.ID)
		return err
	})
	if err != nil || got.Enquiry.State() != enquiries.StateUnderReview || got.Enquiry.Version() != 2 || len(got.Transitions) != 1 {
		t.Fatal("new statement did not see committed control", err)
	}
}

func TestIntegrationLoadTimestampBoundaries(t *testing.T) {
	db, admin, role := database(t)
	for i, at := range []time.Time{time.Date(1, 1, 1, 0, 0, 0, 1000, time.UTC), time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)} {
		r, h := namedFixture(1, "time-"+string(rune('a'+i)), "org-2")
		r.Created, r.Changed, h[0].At = stamp(at), stamp(at), stamp(at)
		if i == 0 {
			r.Start.Time = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
			r.End.Time = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
		} else {
			r.Start.Valid, r.End.Valid = false, false
			r.Start.Time, r.End.Time = time.Time{}, time.Time{}
		}
		seed(t, admin, r, h)
		var got Loaded
		err := db.WithTx(context.Background(), pg.Scope{OrganizationID: "org-2", ActorID: "actor-1"}, func(ctx context.Context, tx pg.Executor) error {
			if err := restricted(ctx, tx, role); err != nil {
				return err
			}
			var err error
			got, err = Load(ctx, tx, "org-2", r.ID)
			return err
		})
		if err != nil || !got.Enquiry.CreatedAt().Equal(at) || got.Enquiry.CreatedAt().Nanosecond() != at.Nanosecond() {
			t.Fatal("database timestamp boundary changed", err)
		}
		if i == 0 && (got.Enquiry.Input().TravelStart != "0001-01-01" || got.Enquiry.Input().TravelEnd != "9999-12-31") {
			t.Fatal("calendar range changed")
		}
		if i == 1 && (got.Enquiry.Input().TravelStart != "" || got.Enquiry.Input().TravelEnd != "") {
			t.Fatal("NULL dates changed")
		}
	}
}
