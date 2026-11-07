package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
)

func TestIntegrationCreationCommitTransport(t *testing.T) {
	for _, mode := range []commitWireMode{deliverCommitReply, dropCommitReply, dropCommitQuery} {
		t.Run(string(mode), func(t *testing.T) {
			name := "wire-" + string(mode)
			f := persistent(t, name)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			target := f.admin.Config()
			cfg := pg.DefaultConfig(target.Host, target.Port, target.Database, target.User)
			cfg.MaxConns = 1
			wire := newCommitWireProxy(t, ctx, cfg, mode)
			cfg.Host = wire.dir
			db, err := pg.Open(ctx, cfg)
			if err != nil {
				t.Fatal("open real transaction pool through Unix proxy", err)
			}
			t.Cleanup(func() {
				if err := db.Close(context.Background()); err != nil {
					t.Error("close proxied pool", err)
				}
			})
			creator, err := NewFirstCreator(db, f.identity, f.key[:], f.creator.newID)
			if err != nil {
				t.Fatal(err)
			}
			// The existing fixture adds only restricted role setup. The real DB
			// boundary and pgx decide every transaction outcome.
			creator.authority.db = creationFixtureBoundary{db: db, role: f.role}
			input := captureInput()
			done := startCreation(creator, f.r, recoveryKey, input, ctx)
			var point commitWirePoint
			select {
			case point = <-wire.reached:
			case result := <-done:
				t.Fatal("creation returned before the wire boundary", result.err)
			case <-wire.done:
				t.Fatal("proxy stopped before the wire boundary", wire.relayError())
			case <-ctx.Done():
				t.Fatal("COMMIT did not reach the proxy before the deadline")
			}

			committed := mode != dropCommitQuery
			wantReady := byte('T')
			if committed {
				wantReady = 'I'
			}
			if point.pid <= 0 || point.queryForwarded != committed ||
				(point.replyKinds != "") != committed || point.ready != wantReady {
				t.Fatalf("wrong COMMIT wire boundary: %+v", point)
			}
			assertCommitWireObserver(t, ctx, f, point.pid, !committed)
			var want RecoveredCreation
			counts := [3]int{}
			if committed {
				counts = [3]int{1, 1, 1}
				want = committedWireCreation(t, ctx, f, name)
			}
			// The direct observer checks the database while the driver is still
			// waiting and before the proxy delivers any reply or closes a socket.
			creationCounts(t, f, counts)
			before := recoverySnapshot(t, f)
			select {
			case result := <-done:
				t.Fatal("creation returned while the commit reply was held", result.err)
			default:
			}
			close(wire.release)
			result := completedCreation(t, done)
			if mode == deliverCommitReply {
				if result.err != nil || result.result.Enquiry.ID() != want.EnquiryID ||
					result.result.EventID != want.EventID || !result.result.Audit.At.Equal(want.At) ||
					result.result.Enquiry.State() != enquiries.StateNew || result.result.Enquiry.Input() != input {
					t.Fatal("delivered COMMIT did not yield the expected creation", result.err)
				}
			} else {
				noCreated(t, result, pg.ErrCommitUnknown)
				if result.err != pg.ErrCommitUnknown || ctx.Err() != nil {
					t.Fatal("socket loss did not yield the exact unknown-commit outcome", result.err)
				}
				waitCommitWireBackendGone(t, f, point.pid)
			}
			creationCounts(t, f, counts)

			// Use the same one-slot pool. A healthy connection is retained for
			// the control, and a different backend must replace a broken one.
			var healthyPID int32
			err = db.WithTx(ctx, pg.Scope{OrganizationID: f.r.OrganizationID, ActorID: f.r.ActorID}, func(ctx context.Context, tx pg.Executor) error {
				if err := restricted(ctx, tx, f.role); err != nil {
					return err
				}
				return tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&healthyPID)
			})
			if err != nil || healthyPID <= 0 || (healthyPID == point.pid) != (mode == deliverCommitReply) {
				t.Fatal("unexpected backend reuse after COMMIT", err)
			}
			r := f.r
			for _, attempt := range []string{"wire-recovery-first", "wire-recovery-repeat"} {
				r.RequestID = attempt
				recoverer, identity := recoveryAttempt(t, f, db, r)
				ack, err := recoverer.Recover(ctx, r, recoveryKey, input)
				if identity.calls.Load() != 1 {
					t.Fatal("recovery did not attest the new request")
				}
				if committed {
					if err != nil || ack != want {
						t.Fatal("recovery did not return the original minimal acknowledgement", err)
					}
				} else {
					requireRecoveryFailure(t, ack, err, ErrCreationUnconfirmed)
				}
			}
			r.RequestID, r.MembershipID = "wire-recovery-denied", "unbound-wire-membership"
			denied, _ := recoveryAttempt(t, f, db, r)
			ack, err := denied.Recover(ctx, r, recoveryKey, input)
			requireRecoveryFailure(t, ack, err, authz.ErrUnauthorized)
			if f.ids.Load() != 2 || f.identity.calls.Load() != 1 || recoverySnapshot(t, f) != before {
				t.Fatal("unexpected retry, extra IDs or recovery writes")
			}

			if err := db.Close(context.Background()); err != nil {
				t.Fatal("close proxied pool", err)
			}
			wire.cancel()
			select {
			case <-wire.done:
			case <-time.After(3 * time.Second):
				t.Fatal("commit proxy did not finish cleanup")
			}
			if err := wire.relayError(); err != nil {
				t.Fatal("commit proxy failed", err)
			}
			wantSessions, wantReplies := 2, 0
			if mode == deliverCommitReply {
				wantSessions, wantReplies = 1, len(point.replyKinds)
			}
			if len(wire.sessions) != wantSessions || wire.sessions[0].pid != point.pid ||
				wire.sessions[wantSessions-1].pid != healthyPID || wire.sessions[0].replyFrames != wantReplies {
				t.Fatal("unexpected proxy session or COMMIT reply delivery count")
			}
			for _, session := range wire.sessions {
				waitCommitWireBackendGone(t, f, session.pid)
			}
			t.Logf("wire COMMIT forwarded=%t server reply kinds=%q ReadyForQuery=%c reply frames delivered=%d records=%v client outcome=%v backends=%d all sessions and locks released",
				point.queryForwarded, point.replyKinds, point.ready, wire.sessions[0].replyFrames,
				counts, result.err, len(wire.sessions))
		})
	}
}

func assertCommitWireObserver(t *testing.T, ctx context.Context, f *persistentFixture, pid int32, openTransaction bool) {
	t.Helper()
	var independent, present, holdsXID bool
	err := f.admin.QueryRow(ctx, `SELECT pg_backend_pid() <> $1 AND inet_client_addr() IS NULL,
 EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND datname=current_database()),
 EXISTS (SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='transactionid' AND mode='ExclusiveLock' AND granted)`, pid).
		Scan(&independent, &present, &holdsXID)
	if err != nil || !independent || !present || holdsXID != openTransaction {
		t.Fatal("independent observer did not see the expected transaction boundary", err)
	}
}

func committedWireCreation(t *testing.T, ctx context.Context, f *persistentFixture, name string) RecoveredCreation {
	t.Helper()
	want := RecoveredCreation{
		OrganizationID: f.r.OrganizationID, EnquiryID: "persist-" + name + "-1",
		EventID: "persist-" + name + "-2", Action: "enquiry.created", Version: 1,
	}
	err := f.admin.QueryRow(ctx, `SELECT v.at::timestamptz
 FROM softteros_enquiries.enquiry_command_receipts r
 JOIN softteros_enquiries.enquiry_events v ON v.organization_id=r.organization_id AND v.event_id=r.event_id
 JOIN softteros_enquiries.enquiries e ON e.organization_id=r.organization_id AND e.enquiry_id=r.enquiry_id
 WHERE r.organization_id=$1 AND r.membership_id=$2 AND r.actor_id=$3 AND r.request_key=$4
 AND r.enquiry_id=$5 AND r.event_id=$6 AND r.completed AND r.completed_at>=v.at
 AND r.command='enquiry.created' AND r.expected_version=0 AND r.resulting_version=1 AND r.fingerprint_version=1
 AND v.enquiry_id=e.enquiry_id AND v.request_key=r.request_key AND v.actor_id=r.actor_id AND v.membership_id=r.membership_id
 AND v.action=r.command AND v.outcome='success' AND v.resulting_version=1
 AND e.created_by=r.actor_id AND e.creator_membership_id=r.membership_id AND e.state='New'
 AND e.version=1 AND e.created_at=v.at AND e.last_changed_at=v.at AND e.assignee_membership_id IS NULL`,
		want.OrganizationID, f.r.MembershipID, f.r.ActorID, recoveryKey, want.EnquiryID, want.EventID).Scan(&want.At)
	if err != nil {
		t.Fatal("committed enquiry, event and receipt were not independently verified", err)
	}
	want.At = want.At.UTC()
	return want
}

func waitCommitWireBackendGone(t *testing.T, f *persistentFixture, pid int32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var remains bool
		err := f.admin.QueryRow(ctx, `SELECT
 EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND datname=current_database())
 OR EXISTS (SELECT 1 FROM pg_locks WHERE pid=$1)`, pid).Scan(&remains)
		if err != nil {
			t.Fatal("check run-owned backend and locks", err)
		}
		if !remains {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("run-owned backend %d or its locks remain", pid)
		case <-ticker.C:
		}
	}
}
