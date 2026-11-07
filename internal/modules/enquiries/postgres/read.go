package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries/application"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type ReadIdentityRequest struct{ ActorID, RequestID string }

type ReadAttestation struct {
	Actor     authz.Actor
	RequestID string
}

// ReadIdentity revalidates the authenticated actor and this request against
// current trusted local facts after fencing. Identity changes must use the
// exclusive actor fence. Honor ctx and fail closed without cached attestations,
// external network calls, or human waits while the fences are held.
type ReadIdentity interface {
	CurrentEnquiryRead(context.Context, ReadIdentityRequest) (ReadAttestation, error)
}

type AssignedReader struct {
	db       scopedTransactions
	identity ReadIdentity
}

func NewAssignedReader(db *pg.DB, identity ReadIdentity) (*AssignedReader, error) {
	if db == nil || identity == nil {
		return nil, application.ErrEnquiryReadFailed
	}
	return &AssignedReader{db: db, identity: identity}, nil
}

// GetEnquiry returns the current assigned-work view only after the fenced
// transaction completes. Only the enquiry ID is a business input.
func (r *AssignedReader) GetEnquiry(ctx context.Context, request application.ReadRequest, enquiryID string) (application.EnquiryDetails, error) {
	if r == nil || r.db == nil || r.identity == nil {
		return application.EnquiryDetails{}, application.ErrEnquiryReadFailed
	}
	if !identifier(enquiryID) {
		return application.EnquiryDetails{}, application.ErrInvalidEnquiryID
	}
	if !identifier(request.ActorID) || !identifier(request.OrganizationID) ||
		!identifier(request.MembershipID) || !identifier(request.RequestID) {
		return application.EnquiryDetails{}, application.ErrEnquiryUnavailable
	}
	var candidate application.EnquiryDetails
	err := r.db.WithTx(ctx, pg.Scope{ActorID: request.ActorID, OrganizationID: request.OrganizationID}, func(ctx context.Context, tx pg.Executor) error {
		view, err := r.read(ctx, tx, request, enquiryID)
		candidate = view
		return err
	})
	if err != nil {
		return application.EnquiryDetails{}, safeReadError(ctx, err)
	}
	return candidate, nil
}

func (r *AssignedReader) currentPolicy(ctx context.Context, tx pg.Executor, request application.ReadRequest) (authz.Context, error) {
	actorRevision, organizationRevision, err := lockAuthority(ctx, tx, request.ActorID, request.OrganizationID)
	if err != nil {
		var server *pgconn.PgError
		if errors.As(err, &server) && server.Code == "42501" && server.Message == "authority context unavailable" {
			return authz.Context{}, application.ErrEnquiryUnavailable
		}
		return authz.Context{}, errors.Join(ErrStorage, ctx.Err())
	}
	if actorRevision <= 0 || organizationRevision <= 0 {
		return authz.Context{}, ErrStored
	}
	identity, err := r.identity.CurrentEnquiryRead(ctx, ReadIdentityRequest{ActorID: request.ActorID, RequestID: request.RequestID})
	if err != nil {
		return authz.Context{}, errors.Join(application.ErrEnquiryReadFailed, ctx.Err())
	}
	if identity.RequestID != request.RequestID || identity.Actor.ID != request.ActorID ||
		!identity.Actor.Authenticated || !identity.Actor.Human {
		return authz.Context{}, application.ErrEnquiryUnavailable
	}
	member, err := currentMembership(ctx, tx, request.ActorID, request.OrganizationID, request.MembershipID, authz.CapabilityReadEnquiry)
	if err == authz.ErrUnauthorized {
		return authz.Context{}, application.ErrEnquiryUnavailable
	}
	if err != nil {
		return authz.Context{}, err
	}
	return authz.NewContext(authz.ContextInput{
		Actor: identity.Actor, ActiveOrganizationID: request.OrganizationID, Membership: member,
	}), nil
}

func (r *AssignedReader) read(ctx context.Context, tx pg.Executor, request application.ReadRequest, enquiryID string) (application.EnquiryDetails, error) {
	policy, err := r.currentPolicy(ctx, tx, request)
	if err != nil {
		return application.EnquiryDetails{}, err
	}
	at, err := authorityTime(ctx, tx, time.Time{})
	if err != nil {
		return application.EnquiryDetails{}, err
	}
	if !policy.CanReadAssignedEnquiries(at) {
		return application.EnquiryDetails{}, application.ErrEnquiryUnavailable
	}
	var owner, id, assignee, state string
	var version int64
	err = tx.QueryRow(ctx, lockAssignedEnquirySQL, request.OrganizationID, enquiryID, request.MembershipID,
		string(enquiries.StateUnderReview), string(enquiries.StateQualified)).Scan(&owner, &id, &assignee, &state, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return application.EnquiryDetails{}, application.ErrEnquiryUnavailable
	}
	if err != nil {
		return application.EnquiryDetails{}, errors.Join(ErrStorage, ctx.Err())
	}
	at, err = authorityTime(ctx, tx, at)
	if err != nil {
		return application.EnquiryDetails{}, err
	}
	if id != enquiryID || !policy.CanReadAssignedEnquiry(owner, assignee, at) {
		return application.EnquiryDetails{}, application.ErrEnquiryUnavailable
	}
	view, err := assignedView(id, enquiries.State(state), version)
	if err != nil {
		return application.EnquiryDetails{}, err
	}
	var count int32
	var start, end pgtype.Date
	if err = tx.QueryRow(ctx, assignedTripSQL, owner, id).Scan(&view.Destination, &count, &start, &end); err != nil {
		return application.EnquiryDetails{}, errors.Join(ErrStorage, ctx.Err())
	}
	view.TravellerCount = int(count)
	startDate, validStart := calendar(start)
	endDate, validEnd := calendar(end)
	if !validStart || !validEnd || enquiries.ValidateTravelDetails(view.Destination, view.TravellerCount, startDate, endDate) != nil {
		return application.EnquiryDetails{}, ErrStored
	}
	view.TravelStart, view.TravelEnd = startDate, endDate
	at, err = authorityTime(ctx, tx, at)
	if err != nil {
		return application.EnquiryDetails{}, err
	}
	if !policy.CanReadAssignedEnquiry(owner, assignee, at) {
		return application.EnquiryDetails{}, application.ErrEnquiryUnavailable
	}
	return view, nil
}

func assignedView(id string, state enquiries.State, version int64) (application.EnquiryDetails, error) {
	var expectedVersion int64
	switch state {
	case enquiries.StateUnderReview:
		expectedVersion = 2
	case enquiries.StateQualified:
		expectedVersion = 3
	default:
		return application.EnquiryDetails{}, application.ErrEnquiryUnavailable
	}
	if version != expectedVersion {
		return application.EnquiryDetails{}, ErrStored
	}
	return application.EnquiryDetails{EnquiryID: id, State: state, Version: uint64(version)}, nil
}

// Keep only safe categories even if a dependency returns raw diagnostics.
// A denial joined with a rollback failure is an operational failure.
func safeReadError(ctx context.Context, err error) error {
	if err == application.ErrEnquiryUnavailable && ctx.Err() == nil {
		return err
	}
	safe := []error{application.ErrEnquiryReadFailed, ctx.Err()}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, ErrStorage, ErrStored,
		pg.ErrCleanup, pg.ErrCommitRejected, pg.ErrCommitUnknown} {
		if errors.Is(err, cause) && ctx.Err() != cause {
			safe = append(safe, cause)
		}
	}
	return errors.Join(safe...)
}

// The scope filters avoid locking inaccessible rows. Check the row returned
// after any wait before selecting private trip fields on this same connection.
const lockAssignedEnquirySQL = `SELECT e.organization_id::text,e.enquiry_id::text,e.assignee_membership_id::text,e.state,e.version
FROM softteros_enquiries.enquiries e
WHERE e.organization_id=$1 AND e.enquiry_id=$2 AND e.assignee_membership_id=$3 AND e.state IN ($4,$5)
 AND softteros_access.context_organization()=$1
FOR SHARE OF e`

const assignedTripSQL = `SELECT e.destination,e.traveller_count,e.travel_start,e.travel_end
FROM softteros_enquiries.enquiries e
WHERE e.organization_id=$1 AND e.enquiry_id=$2 AND softteros_access.context_organization()=$1`
