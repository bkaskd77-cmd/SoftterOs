package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries/application"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrCreateConfiguration = errors.New("persistent enquiry creator is not configured")
	ErrDuplicateCreation   = errors.New("enquiry request already used")
)

// FirstCreator persists a first-attempt creation only. Entry code must establish
// the trusted actor/request identity; selectors and fingerprints are not authority.
// All dependencies must honor the operation's bounded, local-only work contract.
type FirstCreator struct {
	authority *CreationChecker
	secret    [32]byte
	newID     func() (string, error)
}

// newID is a trusted, concurrency-safe server generator used for enquiry and event
// IDs, only after authorization and input validation. No production generator or
// key provisioning is supplied. Copy the explicit secret; never log this object.
func NewFirstCreator(db *pg.DB, identity CreationIdentity, secret []byte, newID func() (string, error)) (*FirstCreator, error) {
	if len(secret) != 32 || newID == nil {
		return nil, ErrCreateConfiguration
	}
	authority, err := NewCreationChecker(db, identity)
	if err != nil {
		return nil, ErrCreateConfiguration
	}
	c := &FirstCreator{authority: authority, newID: newID}
	copy(c.secret[:], secret)
	return c, nil
}

// Created is returned only after an acknowledged commit. Errors always return
// its zero value, including uncertain commit and cleanup outcomes.
type Created struct {
	Enquiry enquiries.Enquiry
	Audit   enquiries.CreationAudit
	EventID string
}

func (c *FirstCreator) Create(ctx context.Context, request CreationRequest, requestKey string, input enquiries.Input) (Created, error) {
	if c == nil || c.authority == nil || c.authority.db == nil || c.authority.identity == nil || c.newID == nil {
		return Created{}, ErrCreateConfiguration
	}
	if !validCreationRequest(request) {
		return Created{}, authz.ErrUnauthorized
	}
	if !identifier(requestKey) {
		return Created{}, ErrSelector
	}
	var candidate Created
	err := c.authority.db.WithTx(ctx, pg.Scope{ActorID: request.ActorID, OrganizationID: request.OrganizationID}, func(ctx context.Context, tx pg.Executor) error {
		facts, err := c.authority.acquire(ctx, tx, request)
		if err != nil {
			return err
		}
		fingerprint, err := creationFingerprint(c.secret, facts.authorization, requestKey, input)
		if err != nil {
			return err
		}
		a := facts.authorization
		tag, err := tx.Exec(ctx, reserveCreationSQL, a.OrganizationID(), a.MembershipID(), requestKey, a.ActorID(), fingerprint[:])
		if err != nil {
			return creationStorageError(ctx)
		}
		if tag.RowsAffected() == 0 {
			return ErrDuplicateCreation
		}
		if tag.RowsAffected() != 1 {
			return ErrStorage
		}
		// Reservation may wait for another transaction. Obtain the action instant
		// after that wait; retain it in domain/audit values through final checks.
		if err := facts.refresh(ctx, tx); err != nil {
			return err
		}
		actionAt := facts.authorization.AuthorizedAt()
		creator, err := application.NewCreator(func() time.Time { return actionAt }, c.newID)
		if err != nil {
			return ErrCreateConfiguration
		}
		result, err := creator.Create(facts.policy, input)
		if err != nil {
			return err
		}
		eventID, err := c.newID()
		if err != nil {
			return application.ErrIdentifierGeneration
		}
		if !identifier(eventID) {
			return enquiries.ErrInvalidID
		}
		e, audit := result.Enquiry, result.Audit
		start, err := creationDate(e.Input().TravelStart)
		if err != nil {
			return err
		}
		end, err := creationDate(e.Input().TravelEnd)
		if err != nil {
			return err
		}
		if err = creationWrite(ctx, tx, insertCreationSQL, e.OrganizationID(), e.ID(), input.ContactName, input.ContactEmail,
			input.Destination, input.TravellerCount, start, end, e.CreatedBy(), e.MembershipID(), e.CreatedAt()); err != nil {
			return err
		}
		if err = creationWrite(ctx, tx, insertCreationEventSQL, audit.OrganizationID, eventID, audit.EnquiryID, requestKey,
			audit.ActorID, audit.MembershipID, audit.Action, string(audit.Capability), facts.actorRevision, facts.organizationRevision, audit.At); err != nil {
			return err
		}
		if err = facts.refresh(ctx, tx); err != nil {
			return err
		}
		if err = creationWrite(ctx, tx, completeCreationSQL, audit.OrganizationID, audit.MembershipID, requestKey, audit.ActorID,
			fingerprint[:], e.ID(), eventID, facts.authorization.AuthorizedAt()); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, creationIntegritySQL); err != nil {
			return creationStorageError(ctx)
		}
		// No writes or blocking collaborators after integrity checks and this
		// final refresh. The unchanged transaction boundary alone owns commit.
		if err = facts.refresh(ctx, tx); err != nil {
			return err
		}
		candidate = Created{Enquiry: e, Audit: audit, EventID: eventID}
		return nil
	})
	if err != nil {
		// Keep ErrCommitRejected, ErrCommitUnknown and ErrCleanup distinct.
		return Created{}, err
	}
	return candidate, nil
}

func creationDate(value string) (pgtype.Date, error) {
	if value == "" {
		return pgtype.Date{}, nil
	}
	d, err := time.Parse("2006-01-02", value)
	if err != nil || d.Year() < 1 || d.Year() > 9999 || d.Format("2006-01-02") != value {
		return pgtype.Date{}, enquiries.ErrInvalidInput
	}
	// Year 0001-01-01 is a valid calendar date, including Go's zero instant.
	return pgtype.Date{Time: d, Valid: true}, nil
}

func creationStorageError(ctx context.Context) error { return errors.Join(ErrStorage, ctx.Err()) }

func creationWrite(ctx context.Context, tx pg.Executor, query string, args ...any) error {
	tag, err := tx.Exec(ctx, query, args...)
	if err != nil {
		return creationStorageError(ctx)
	}
	if tag.RowsAffected() != 1 {
		return ErrStorage
	}
	return nil
}

const reserveCreationSQL = `INSERT INTO softteros_enquiries.enquiry_command_receipts
 (organization_id,membership_id,request_key,actor_id,command,expected_version,fingerprint_version,fingerprint)
 VALUES($1,$2,$3,$4,'enquiry.created',0,1,$5)
 ON CONFLICT (organization_id,membership_id,request_key) DO NOTHING`

const insertCreationSQL = `INSERT INTO softteros_enquiries.enquiries
 (organization_id,enquiry_id,contact_name,contact_email,destination,traveller_count,travel_start,travel_end,
 state,created_by,creator_membership_id,created_at,assignee_membership_id,version,last_changed_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,'New',$9,$10,$11,NULL,1,$11)`

const insertCreationEventSQL = `INSERT INTO softteros_enquiries.enquiry_events
 (organization_id,event_id,enquiry_id,request_key,active_organization_id,actor_id,membership_id,
 action,capability,outcome,actor_authority_revision,organization_authority_revision,new_state,resulting_version,at)
 VALUES($1,$2,$3,$4,$1,$5,$6,$7,$8,'success',$9,$10,'New',1,$11)`

const completeCreationSQL = `UPDATE softteros_enquiries.enquiry_command_receipts
 SET enquiry_id=$6,event_id=$7,resulting_version=1,completed=true,completed_at=$8
 WHERE organization_id=$1 AND membership_id=$2 AND request_key=$3 AND actor_id=$4
 AND command='enquiry.created' AND expected_version=0 AND fingerprint_version=1 AND fingerprint=$5 AND NOT completed`

const creationIntegritySQL = `SET CONSTRAINTS ALL IMMEDIATE`
