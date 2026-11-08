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

var (
	ErrReviewConfiguration        = errors.New("persistent enquiry review is not configured")
	ErrReviewAuthorityUnavailable = errors.New("enquiry review authority unavailable")
	ErrDuplicateReview            = errors.New("enquiry request already used")
)

// ReviewRequest comes from trusted entry code. ActorID and RequestID bind the
// current attempt. The organization and membership selectors require database
// verification, and RequestID is separate from the command receipt key.
type ReviewRequest struct {
	ActorID, OrganizationID, MembershipID, RequestID string
}

type ReviewIdentityRequest struct{ ActorID, RequestID string }

type ReviewAttestation struct {
	Actor     authz.Actor
	RequestID string
}

// ReviewIdentity must check current local actor and request facts under the
// shared fences, honor ctx, and fail closed. Identity changes require the
// exclusive actor fence. The adapter must return promptly without external work.
type ReviewIdentity interface {
	CurrentEnquiryReview(context.Context, ReviewIdentityRequest) (ReviewAttestation, error)
}

type ReviewStarter struct {
	db         scopedTransactions
	identity   ReviewIdentity
	secret     [32]byte
	newEventID func() (string, error)
}

// NewReviewStarter copies the dedicated review key. newEventID is a trusted,
// concurrency-safe local generator that must return promptly under locks.
func NewReviewStarter(db *pg.DB, identity ReviewIdentity, secret []byte, newEventID func() (string, error)) (*ReviewStarter, error) {
	if db == nil || identity == nil || len(secret) != 32 || newEventID == nil {
		return nil, ErrReviewConfiguration
	}
	r := &ReviewStarter{db: db, identity: identity, newEventID: newEventID}
	copy(r.secret[:], secret)
	return r, nil
}

// StartedReview acknowledges only the committed transition. Every error,
// including an unknown commit outcome, returns its zero value.
type StartedReview struct {
	OrganizationID, EnquiryID, EventID, AssigneeMembershipID string
	State                                                    enquiries.State
	Version                                                  uint64
	At                                                       time.Time
}

func (r *ReviewStarter) StartReview(ctx context.Context, request ReviewRequest, enquiryID string, expectedVersion uint64, requestKey string) (StartedReview, error) {
	if r == nil || r.db == nil || r.identity == nil || r.newEventID == nil {
		return StartedReview{}, ErrReviewConfiguration
	}
	if !identifier(request.ActorID) || !identifier(request.OrganizationID) ||
		!identifier(request.MembershipID) || !identifier(request.RequestID) {
		return StartedReview{}, authz.ErrTransitionUnauthorized
	}
	if !identifier(enquiryID) || !identifier(requestKey) {
		return StartedReview{}, ErrSelector
	}
	var candidate StartedReview
	err := r.db.WithTx(ctx, pg.Scope{ActorID: request.ActorID, OrganizationID: request.OrganizationID}, func(ctx context.Context, tx pg.Executor) error {
		var err error
		candidate, err = r.startReview(ctx, tx, request, enquiryID, expectedVersion, requestKey)
		return err
	})
	if err != nil {
		return StartedReview{}, err
	}
	return candidate, nil
}

type reviewAuthority struct {
	actor                               authz.Actor
	member                              authz.Membership
	actorRevision, organizationRevision int64
	grantID                             string
	checkedAt                           time.Time
}

func (r *ReviewStarter) currentAuthority(ctx context.Context, tx pg.Executor, request ReviewRequest) (reviewAuthority, error) {
	actorRevision, organizationRevision, err := lockAuthority(ctx, tx, request.ActorID, request.OrganizationID)
	if err != nil {
		var server *pgconn.PgError
		if errors.As(err, &server) && server.Code == "42501" && server.Message == "authority context unavailable" {
			return reviewAuthority{}, authz.ErrTransitionUnauthorized
		}
		return reviewAuthority{}, errors.Join(ErrStorage, ctx.Err())
	}
	if actorRevision <= 0 || organizationRevision <= 0 {
		return reviewAuthority{}, ErrStored
	}
	identity, err := r.identity.CurrentEnquiryReview(ctx, ReviewIdentityRequest{ActorID: request.ActorID, RequestID: request.RequestID})
	if err != nil {
		return reviewAuthority{}, errors.Join(ErrReviewAuthorityUnavailable, ctx.Err())
	}
	if identity.RequestID != request.RequestID || identity.Actor.ID != request.ActorID ||
		!identity.Actor.Authenticated || !identity.Actor.Human {
		return reviewAuthority{}, authz.ErrTransitionUnauthorized
	}
	member, err := currentMembership(ctx, tx, request.ActorID, request.OrganizationID, request.MembershipID, authz.CapabilityReviewEnquiry)
	if err == authz.ErrUnauthorized {
		return reviewAuthority{}, authz.ErrTransitionUnauthorized
	}
	if err != nil {
		return reviewAuthority{}, err
	}
	return reviewAuthority{actor: identity.Actor, member: member, actorRevision: actorRevision, organizationRevision: organizationRevision}, nil
}

// The fences stabilize identity and policy rows. Time can still change which
// grants are eligible while a command waits. Recheck cardinality and the same
// grant at each fresh decision instant.
func (f *reviewAuthority) authorize(ctx context.Context, tx pg.Executor, org, id string) (authz.EnquiryTransitionAuthorization, error) {
	at, err := authorityTime(ctx, tx, f.checkedAt)
	if err != nil {
		return authz.EnquiryTransitionAuthorization{}, err
	}
	grant, err := eligibleReviewGrant(ctx, tx, f.member, id, at)
	if err != nil {
		return authz.EnquiryTransitionAuthorization{}, err
	}
	if f.grantID != "" && grant.ID != f.grantID {
		return authz.EnquiryTransitionAuthorization{}, authz.ErrTransitionUnauthorized
	}
	policy := authz.NewContext(authz.ContextInput{
		Actor: f.actor, ActiveOrganizationID: f.member.OrganizationID, Membership: f.member, TransitionGrant: grant,
	})
	proof, err := policy.AuthorizeEnquiryTransition(id, org, authz.CapabilityReviewEnquiry, at)
	if err == nil {
		f.grantID, f.checkedAt = grant.ID, at
	}
	return proof, err
}

func eligibleReviewGrant(ctx context.Context, tx pg.Executor, member authz.Membership, id string, at time.Time) (authz.EnquiryTransitionGrant, error) {
	rows, err := tx.Query(ctx, eligibleReviewGrantSQL, member.OrganizationID, member.ActorID, member.ID, id,
		string(authz.CapabilityReviewEnquiry), at)
	if err != nil {
		return authz.EnquiryTransitionGrant{}, errors.Join(ErrStorage, ctx.Err())
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return authz.EnquiryTransitionGrant{}, errors.Join(ErrStorage, ctx.Err())
		}
		return authz.EnquiryTransitionGrant{}, authz.ErrTransitionUnauthorized
	}
	var grant authz.EnquiryTransitionGrant
	var capability string
	var from, until pgtype.Timestamptz
	if err := rows.Scan(&grant.ID, &grant.OrganizationID, &grant.ActorID, &grant.MembershipID,
		&grant.EnquiryID, &capability, &grant.Active, &grant.Revoked, &from, &until); err != nil {
		return authz.EnquiryTransitionGrant{}, errors.Join(ErrStored, ctx.Err())
	}
	if rows.Next() {
		return authz.EnquiryTransitionGrant{}, authz.ErrTransitionUnauthorized
	}
	if rows.Err() != nil {
		return authz.EnquiryTransitionGrant{}, errors.Join(ErrStorage, ctx.Err())
	}
	if !instant(from) || !instant(until) {
		return authz.EnquiryTransitionGrant{}, ErrStored
	}
	grant.ValidFrom, grant.ValidUntil = from.Time.UTC(), until.Time.UTC()
	grant.Capability = authz.Capability(capability)
	return grant, nil
}

func (r *ReviewStarter) startReview(ctx context.Context, tx pg.Executor, request ReviewRequest, enquiryID string, expectedVersion uint64, requestKey string) (StartedReview, error) {
	facts, err := r.currentAuthority(ctx, tx, request)
	if err != nil {
		return StartedReview{}, err
	}
	preflight, err := facts.authorize(ctx, tx, request.OrganizationID, enquiryID)
	if err != nil {
		return StartedReview{}, err
	}
	if expectedVersion != 1 {
		return StartedReview{}, enquiries.ErrVersionConflict
	}
	mac, err := reviewFingerprint(r.secret, preflight, enquiryID, requestKey)
	if err != nil {
		return StartedReview{}, err
	}
	org := preflight.OrganizationID()
	tag, err := tx.Exec(ctx, reserveReviewSQL, org, preflight.MembershipID(), requestKey, preflight.ActorID(), enquiryID, mac[:])
	if err != nil {
		return StartedReview{}, errors.Join(ErrStorage, ctx.Err())
	}
	// Uniqueness may have blocked. Recheck before reporting a duplicate or
	// acquiring the row lock, which always follows the receipt reservation.
	if _, err := facts.authorize(ctx, tx, org, enquiryID); err != nil {
		return StartedReview{}, err
	}
	switch tag.RowsAffected() {
	case 0:
		return StartedReview{}, ErrDuplicateReview
	case 1:
	default:
		return StartedReview{}, ErrStorage
	}

	var owner, id, state string
	var version int64
	var assignee pgtype.Text
	err = tx.QueryRow(ctx, lockReviewEnquirySQL, org, enquiryID).Scan(&owner, &id, &state, &version, &assignee)
	if errors.Is(err, pgx.ErrNoRows) {
		return StartedReview{}, authz.ErrTransitionUnauthorized
	}
	if err != nil {
		return StartedReview{}, errors.Join(ErrStorage, ctx.Err())
	}
	if owner != org || id != enquiryID {
		return StartedReview{}, authz.ErrTransitionUnauthorized
	}
	if _, err := facts.authorize(ctx, tx, owner, id); err != nil {
		return StartedReview{}, err
	}
	if version != int64(expectedVersion) {
		return StartedReview{}, enquiries.ErrVersionConflict
	}
	if state != string(enquiries.StateNew) || assignee.Valid {
		return StartedReview{}, enquiries.ErrInvalidTransition
	}
	loaded, err := Load(ctx, tx, owner, id)
	if err == ErrNotFound {
		return StartedReview{}, authz.ErrTransitionUnauthorized
	}
	if err != nil {
		return StartedReview{}, errors.Join(err, ctx.Err())
	}
	proof, err := facts.authorize(ctx, tx, loaded.Enquiry.OrganizationID(), loaded.Enquiry.ID())
	if err != nil {
		return StartedReview{}, err
	}
	result, err := loaded.Enquiry.StartReview(proof, expectedVersion, proof.AuthorizedAt())
	if err != nil {
		return StartedReview{}, err
	}
	eventID, err := r.newEventID()
	if err != nil {
		return StartedReview{}, application.ErrIdentifierGeneration
	}
	if !identifier(eventID) {
		return StartedReview{}, enquiries.ErrInvalidID
	}
	audit := result.Audit
	tag, err = tx.Exec(ctx, updateReviewEnquirySQL, audit.OrganizationID, audit.EnquiryID, int64(audit.PreviousVersion),
		string(audit.NewState), audit.AssigneeMembershipID, int64(audit.Version), audit.At)
	if err != nil {
		return StartedReview{}, errors.Join(ErrStorage, ctx.Err())
	}
	if tag.RowsAffected() == 0 {
		return StartedReview{}, enquiries.ErrVersionConflict
	}
	if tag.RowsAffected() != 1 {
		return StartedReview{}, ErrStorage
	}
	if err := creationWrite(ctx, tx, insertReviewEventSQL, audit.OrganizationID, eventID, audit.EnquiryID, requestKey,
		audit.ActiveOrganizationID, audit.ActorID, audit.MembershipID, audit.GrantID, audit.Action, string(audit.Capability),
		facts.actorRevision, facts.organizationRevision, string(audit.PreviousState), string(audit.NewState),
		audit.AssigneeMembershipID, int64(audit.PreviousVersion), int64(audit.Version), audit.At); err != nil {
		return StartedReview{}, err
	}
	completedAt, err := authorityTime(ctx, tx, audit.At)
	if err != nil {
		return StartedReview{}, err
	}
	facts.checkedAt = completedAt
	if err := creationWrite(ctx, tx, completeReviewSQL, audit.OrganizationID, audit.MembershipID, requestKey,
		audit.ActorID, audit.EnquiryID, mac[:], eventID, int64(audit.Version), completedAt); err != nil {
		return StartedReview{}, err
	}
	if _, err := tx.Exec(ctx, reviewIntegritySQL); err != nil {
		return StartedReview{}, errors.Join(ErrStorage, ctx.Err())
	}
	// Use the final proof only as an expiry/cardinality gate. Preserve the
	// original action instant in the row, event and acknowledgement.
	if _, err := facts.authorize(ctx, tx, audit.OrganizationID, audit.EnquiryID); err != nil {
		return StartedReview{}, err
	}
	return StartedReview{OrganizationID: audit.OrganizationID, EnquiryID: audit.EnquiryID, EventID: eventID,
		AssigneeMembershipID: audit.AssigneeMembershipID, State: audit.NewState, Version: audit.Version, At: audit.At}, nil
}

const eligibleReviewGrantSQL = `SELECT g.grant_id::text,g.organization_id::text,g.actor_id::text,
 g.membership_id::text,g.enquiry_id::text,g.capability,g.active,g.revoked,
 g.valid_from::timestamptz,g.valid_until::timestamptz
 FROM softteros_access.enquiry_transition_grants g
 WHERE g.organization_id=$1 AND g.actor_id=$2 AND g.membership_id=$3 AND g.enquiry_id=$4 AND g.capability=$5
  AND g.active AND NOT g.revoked AND g.valid_from<=$6::timestamptz AND $6::timestamptz<g.valid_until
  AND softteros_access.context_organization()=$1 AND softteros_access.context_actor()=$2
 LIMIT 2`

const reserveReviewSQL = `INSERT INTO softteros_enquiries.enquiry_command_receipts
 (organization_id,membership_id,request_key,actor_id,command,expected_version,fingerprint_version,enquiry_id,fingerprint)
 VALUES($1,$2,$3,$4,'enquiry.review_started',1,1,$5,$6)
 ON CONFLICT (organization_id,membership_id,request_key) DO NOTHING`

// The enquiry key is unchanged. The write lock serializes claims and conflicts
// with the assigned reader's FOR SHARE while remaining compatible with FK key-share locks.
const lockReviewEnquirySQL = `SELECT e.organization_id::text,e.enquiry_id::text,e.state,e.version,e.assignee_membership_id::text
 FROM softteros_enquiries.enquiries e
 WHERE e.organization_id=$1 AND e.enquiry_id=$2 AND softteros_access.context_organization()=$1
 FOR NO KEY UPDATE OF e`

const updateReviewEnquirySQL = `UPDATE softteros_enquiries.enquiries
 SET state=$4,assignee_membership_id=$5,version=$6,last_changed_at=$7
 WHERE organization_id=$1 AND enquiry_id=$2 AND version=$3 AND state='New' AND assignee_membership_id IS NULL`

const insertReviewEventSQL = `INSERT INTO softteros_enquiries.enquiry_events
 (organization_id,event_id,enquiry_id,request_key,active_organization_id,actor_id,membership_id,grant_id,action,capability,
 outcome,actor_authority_revision,organization_authority_revision,previous_state,new_state,previous_assignee_membership_id,
 assignee_membership_id,previous_version,resulting_version,at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'success',$11,$12,$13,$14,NULL,$15,$16,$17,$18)`

const completeReviewSQL = `UPDATE softteros_enquiries.enquiry_command_receipts
 SET event_id=$7,resulting_version=$8,completed=true,completed_at=$9
 WHERE organization_id=$1 AND membership_id=$2 AND request_key=$3 AND actor_id=$4 AND enquiry_id=$5
  AND command='enquiry.review_started' AND expected_version=1 AND fingerprint_version=1 AND fingerprint=$6
  AND NOT completed AND event_id IS NULL AND resulting_version IS NULL AND completed_at IS NULL`

const reviewIntegritySQL = `SET CONSTRAINTS ALL IMMEDIATE`
