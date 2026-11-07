package postgres

import (
	"context"
	"errors"

	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrCreationConfiguration = errors.New("enquiry creation authority is not configured")
	ErrCreationUnavailable   = errors.New("enquiry creation authority unavailable")
)

// CreationRequest contains selectors from trusted entry code, not permission
// claims. ActorID must already identify the authenticated caller. RequestID must
// identify that same server-side request; it is not an idempotency/receipt key.
type CreationRequest struct {
	ActorID, OrganizationID, MembershipID, RequestID string
}

type CreationIdentityRequest struct{ ActorID, RequestID string }
type CreationAttestation struct {
	Actor     authz.Actor
	RequestID string
}

// CreationIdentity is a mandatory trusted, coordinated identity boundary, not an
// implementation of authentication. CurrentCreation runs after shared fences
// are acquired. It must revalidate this actor/request using current local facts,
// honor ctx and fail if unavailable; never return a cached/always-allow decision.
// Identity changes must obey the exclusive actor-fence protocol. No external
// network calls or human waits may occur under these locks. No provider is supplied.
type CreationIdentity interface {
	CurrentCreation(context.Context, CreationIdentityRequest) (CreationAttestation, error)
}

type CreationChecker struct {
	db       creationTransactions
	identity CreationIdentity
}

type creationTransactions interface {
	WithTx(context.Context, pg.Scope, func(context.Context, pg.Executor) error) error
}

func NewCreationChecker(db *pg.DB, identity CreationIdentity) (*CreationChecker, error) {
	if db == nil || identity == nil {
		return nil, ErrCreationConfiguration
	}
	return &CreationChecker{db: db, identity: identity}, nil
}

// Check evaluates only enquiries.create, holding fences until the existing
// transaction boundary commits/rolls back. It returns no facts, context or token
// that could authorize a later operation. Nil acknowledges only this completed
// check, not permission for a subsequent transaction. No business/audit writes
// or application operation are implemented. Future writes must compose current
// authorization and expiry checks with their writes in one transaction.
func (c *CreationChecker) Check(ctx context.Context, request CreationRequest) error {
	if c == nil || c.db == nil || c.identity == nil {
		return ErrCreationConfiguration
	}
	if !validCreationRequest(request) {
		return authz.ErrUnauthorized
	}
	return c.db.WithTx(ctx, pg.Scope{ActorID: request.ActorID, OrganizationID: request.OrganizationID}, func(ctx context.Context, tx pg.Executor) error {
		return c.authorize(ctx, tx, request)
	})
}

func validCreationRequest(r CreationRequest) bool {
	return identifier(r.ActorID) && identifier(r.OrganizationID) && identifier(r.MembershipID) && identifier(r.RequestID)
}

// authorize is private to the adapter. All facts/proofs remain on this stack;
// callers cannot retain a creation proof across transactions or requests.
func (c *CreationChecker) authorize(ctx context.Context, tx pg.Executor, r CreationRequest) error {
	facts, err := c.acquire(ctx, tx, r)
	if err != nil {
		return err
	}
	return facts.refresh(ctx, tx)
}

// creationFacts never leaves its owning transaction. The creation writer uses
// this same acquisition path, then refreshes after waits and after integrity
// checks. Neither this value nor its authorization is a reusable public token.
type creationFacts struct {
	policy                              authz.Context
	authorization                       authz.CreationAuthorization
	actorRevision, organizationRevision int64
}

func (c *CreationChecker) acquire(ctx context.Context, tx pg.Executor, r CreationRequest) (*creationFacts, error) {
	var actorRevision, organizationRevision int64
	if err := tx.QueryRow(ctx, creationFenceSQL, r.ActorID, r.OrganizationID).Scan(&actorRevision, &organizationRevision); err != nil {
		var server *pgconn.PgError
		if errors.As(err, &server) && server.Code == "42501" {
			return nil, authz.ErrUnauthorized
		}
		return nil, creationUnavailable(ctx)
	}
	if actorRevision <= 0 || organizationRevision <= 0 {
		return nil, ErrCreationUnavailable
	}
	identity, err := c.identity.CurrentCreation(ctx, CreationIdentityRequest{ActorID: r.ActorID, RequestID: r.RequestID})
	if err != nil {
		return nil, creationUnavailable(ctx)
	}
	if identity.RequestID != r.RequestID || identity.Actor.ID != r.ActorID || !identity.Actor.Authenticated {
		return nil, authz.ErrUnauthorized
	}
	var actor, organization string
	var member authz.Membership
	var from, until pgtype.Timestamptz
	var canCreate bool
	err = tx.QueryRow(ctx, creationFactsSQL, r.ActorID, r.OrganizationID, r.MembershipID, string(authz.CapabilityCreateEnquiry)).Scan(
		&actor, &organization, &member.ID, &member.ActorID, &member.OrganizationID,
		&member.Active, &member.Revoked, &from, &until, &canCreate)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, authz.ErrUnauthorized
	}
	if err != nil || !instant(from) || !instant(until) {
		return nil, creationUnavailable(ctx)
	}
	if actor != r.ActorID || organization != r.OrganizationID || member.ID != r.MembershipID ||
		member.ActorID != r.ActorID || member.OrganizationID != r.OrganizationID {
		return nil, authz.ErrUnauthorized
	}
	member.ValidFrom, member.ValidUntil = from.Time.UTC(), until.Time.UTC()
	if canCreate {
		member.Capabilities = []authz.Capability{authz.CapabilityCreateEnquiry}
	}
	facts := &creationFacts{
		policy:        authz.NewContext(authz.ContextInput{Actor: identity.Actor, ActiveOrganizationID: organization, Membership: member}),
		actorRevision: actorRevision, organizationRevision: organizationRevision,
	}
	if err := facts.refresh(ctx, tx); err != nil {
		return nil, err
	}
	return facts, nil
}

// refresh checks locked facts with fresh server time. A final call must follow
// all deferred integrity work; no check promises validity at a future commit instant.
func (f *creationFacts) refresh(ctx context.Context, tx pg.Executor) error {
	var at pgtype.Timestamptz
	if err := tx.QueryRow(ctx, creationClockSQL).Scan(&at); err != nil || !instant(at) ||
		(f.authorization.Valid() && at.Time.Before(f.authorization.AuthorizedAt())) {
		return creationUnavailable(ctx)
	}
	authorization, err := f.policy.AuthorizeEnquiryCreation(at.Time)
	if err == nil {
		f.authorization = authorization
	}
	return err
}

func creationUnavailable(ctx context.Context) error {
	return errors.Join(ErrCreationUnavailable, ctx.Err())
}

const creationFenceSQL = `SELECT actor_revision,organization_revision
FROM softteros_access.lock_current_authority($1,$2)`

const creationClockSQL = `SELECT clock_timestamp()`

// A separate READ COMMITTED statement after the lock helper observes any writer
// that committed before our shared locks. No pre-wait membership/capability read.
const creationFactsSQL = `SELECT a.actor_id::text,o.organization_id::text,
 m.membership_id::text,m.actor_id::text,m.organization_id::text,m.active,m.revoked,
 m.valid_from::timestamptz,m.valid_until::timestamptz,
 EXISTS(SELECT 1 FROM softteros_access.membership_enquiry_capabilities c
   WHERE c.organization_id=m.organization_id AND c.membership_id=m.membership_id AND c.capability=$4)
FROM softteros_access.actors a
JOIN softteros_access.memberships m ON m.actor_id=a.actor_id AND m.organization_id=$2
JOIN softteros_access.organizations o ON o.organization_id=m.organization_id
WHERE a.actor_id=$1 AND o.organization_id=$2 AND m.membership_id=$3
 AND softteros_access.context_actor()=$1 AND softteros_access.context_organization()=$2`
