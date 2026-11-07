package postgres

import (
	"context"
	"crypto/hmac"
	"errors"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	// ErrCreationUnconfirmed means this read found no confirmed completion.
	// The original transaction may still commit.
	ErrCreationUnconfirmed = errors.New("enquiry creation completion unconfirmed")
	ErrCreationMismatch    = errors.New("enquiry creation request does not match receipt")
)

// RecoveredCreation acknowledges a historical committed creation only. Version
// and At come from the original creation, independent of the enquiry's current
// state. The acknowledgement confers no read or mutation authority.
type RecoveredCreation struct {
	OrganizationID, EnquiryID, EventID string
	Action                             string
	Version                            uint64
	At                                 time.Time
}

// Recover checks a prior manual creation using the original key and input, and
// a CreationRequest bound by trusted entry code to the current attempt. It uses
// the explicitly configured creation fingerprint secret and performs no record
// writes. Every error returns a zero acknowledgement.
func (c *FirstCreator) Recover(ctx context.Context, request CreationRequest, requestKey string, input enquiries.Input) (RecoveredCreation, error) {
	if c == nil || c.authority == nil || c.authority.db == nil || c.authority.identity == nil {
		return RecoveredCreation{}, ErrCreateConfiguration
	}
	if !validCreationRequest(request) {
		return RecoveredCreation{}, authz.ErrUnauthorized
	}
	if !identifier(requestKey) {
		return RecoveredCreation{}, ErrSelector
	}

	var candidate RecoveredCreation
	err := c.authority.db.WithTx(ctx, pg.Scope{ActorID: request.ActorID, OrganizationID: request.OrganizationID}, func(ctx context.Context, tx pg.Executor) error {
		facts, err := c.authority.acquire(ctx, tx, request)
		if err != nil {
			return err
		}
		a := facts.authorization
		fingerprint, err := creationFingerprint(c.secret, a, requestKey, input)
		if err != nil {
			return err
		}
		var r creationReceipt
		err = tx.QueryRow(ctx, recoverCreationSQL, a.OrganizationID(), a.MembershipID(), requestKey, a.ActorID(), string(authz.CapabilityCreateEnquiry)).Scan(
			&r.enquiryID, &r.eventID, &r.command, &r.expectedVersion, &r.resultingVersion,
			&r.fingerprintVersion, &r.fingerprint, &r.completed, &r.completedAt, &r.at, &r.resourceMatches)
		var outcome error
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			outcome = ErrCreationUnconfirmed
		case err != nil:
			return errors.Join(ErrStorage, ctx.Err())
		default:
			candidate, outcome = r.acknowledgement(a.OrganizationID(), fingerprint)
		}
		// The SELECT can wait. Recheck the locked facts with fresh database
		// time before releasing any receipt-dependent result, even a mismatch.
		if err := facts.refresh(ctx, tx); err != nil {
			return err
		}
		return outcome
	})
	if err != nil {
		return RecoveredCreation{}, err
	}
	return candidate, nil
}

type creationReceipt struct {
	enquiryID, eventID pgtype.Text
	command            string
	expectedVersion    int64
	resultingVersion   pgtype.Int8
	fingerprintVersion int16
	fingerprint        []byte
	completed          bool
	completedAt, at    pgtype.Timestamptz
	resourceMatches    bool
}

func (r creationReceipt) acknowledgement(org string, fingerprint [32]byte) (RecoveredCreation, error) {
	if r.command != "enquiry.created" || r.expectedVersion != 0 ||
		r.fingerprintVersion != 1 || len(r.fingerprint) != len(fingerprint) {
		return RecoveredCreation{}, ErrStored
	}
	if !r.completed {
		// A creation reservation has no completion fields or joined event.
		if r.enquiryID != (pgtype.Text{}) || r.eventID != (pgtype.Text{}) ||
			r.resultingVersion != (pgtype.Int8{}) || r.completedAt != (pgtype.Timestamptz{}) ||
			r.at != (pgtype.Timestamptz{}) || r.resourceMatches {
			return RecoveredCreation{}, ErrStored
		}
	} else if !r.enquiryID.Valid || !identifier(r.enquiryID.String) || !r.eventID.Valid || !identifier(r.eventID.String) ||
		!r.resultingVersion.Valid || r.resultingVersion.Int64 != 1 || !r.resourceMatches ||
		!instant(r.at) || !instant(r.completedAt) || r.completedAt.Time.Before(r.at.Time) {
		return RecoveredCreation{}, ErrStored
	}
	if !hmac.Equal(r.fingerprint, fingerprint[:]) {
		return RecoveredCreation{}, ErrCreationMismatch
	}
	if !r.completed {
		return RecoveredCreation{}, ErrCreationUnconfirmed
	}
	return RecoveredCreation{
		OrganizationID: org, EnquiryID: r.enquiryID.String, EventID: r.eventID.String,
		Action: r.command, Version: uint64(r.resultingVersion.Int64), At: r.at.Time.UTC(),
	}, nil
}

// The eligible receipt and its original event/resource bindings share a single
// statement snapshot. LEFT JOIN exposes broken bindings as invalid storage. No
// payload or mutable enquiry state is read, and an uncommitted receipt stays
// invisible to this SELECT.
const recoverCreationSQL = `
SELECT r.enquiry_id::text,r.event_id::text,r.command,r.expected_version,r.resulting_version,
 r.fingerprint_version,r.fingerprint,r.completed,r.completed_at::timestamptz,v.at::timestamptz,
 EXISTS(SELECT 1 FROM softteros_enquiries.enquiries e
   WHERE e.organization_id=r.organization_id AND e.enquiry_id=r.enquiry_id
     AND e.created_by=r.actor_id AND e.creator_membership_id=r.membership_id AND e.created_at=v.at)
FROM softteros_enquiries.enquiry_command_receipts r
LEFT JOIN softteros_enquiries.enquiry_events v
 ON v.organization_id=r.organization_id AND v.event_id=r.event_id AND v.enquiry_id=r.enquiry_id
 AND v.active_organization_id=r.organization_id AND v.membership_id=r.membership_id AND v.actor_id=r.actor_id
 AND v.request_key=r.request_key AND v.action=r.command AND v.resulting_version=r.resulting_version
 AND v.capability=$5 AND v.outcome='success' AND v.new_state='New' AND v.grant_id IS NULL
WHERE r.organization_id=$1 AND r.membership_id=$2 AND r.request_key=$3 AND r.actor_id=$4
 AND r.command='enquiry.created' AND softteros_access.context_organization()=$1 AND softteros_access.context_actor()=$4`
