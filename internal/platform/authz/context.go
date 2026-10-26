// Package authz validates trusted, in-process authorization facts.
//
// A future request adapter must authenticate the actor and load current
// membership and effective capabilities from authoritative sources. Constructing
// a Context does not authenticate caller-supplied claims. These types must never
// be populated directly from an untrusted request body.
package authz

import (
	"errors"
	"time"
)

// Capability identifies an effective permission within one membership.
type Capability string

const CapabilityCreateEnquiry Capability = "enquiries.create"

// ErrUnauthorized deliberately does not reveal which authorization fact failed.
var ErrUnauthorized = errors.New("not authorized to create enquiry")

// Actor contains identity facts established by a trusted authentication adapter.
type Actor struct {
	ID            string
	Authenticated bool
}

// Membership contains authoritative facts for one actor in one organization.
// Its validity interval includes ValidFrom and excludes ValidUntil. Capabilities
// must already reflect applicable organization and assignment restrictions.
type Membership struct {
	ID             string
	ActorID        string
	OrganizationID string
	Active         bool
	ValidFrom      time.Time
	ValidUntil     time.Time
	Capabilities   []Capability
}

// ContextInput is supplied only by a trusted server-side adapter.
type ContextInput struct {
	Actor                Actor
	ActiveOrganizationID string
	Membership           Membership
}

// Context is an immutable snapshot of authorization facts. Its zero value denies
// access. It is action-time input, not a session or a durable authorization grant.
type Context struct {
	actor                Actor
	activeOrganizationID string
	membership           Membership
}

// NewContext copies the input, including its mutable capability slice. Every
// action must still call AuthorizeEnquiryCreation with a trusted current time.
func NewContext(input ContextInput) Context {
	membership := input.Membership
	membership.Capabilities = append([]Capability(nil), membership.Capabilities...)
	return Context{
		actor:                input.Actor,
		activeOrganizationID: input.ActiveOrganizationID,
		membership:           membership,
	}
}

// CreationAuthorization is an immutable proof of one successful in-process
// creation check. It records the authorization instant, not a reusable session.
// Its zero value is invalid, and external packages cannot issue their own value.
type CreationAuthorization struct {
	actorID        string
	organizationID string
	membershipID   string
	authorizedAt   time.Time
	validFrom      time.Time
	validUntil     time.Time
	issued         bool
}

// AuthorizeEnquiryCreation denies any missing, malformed, inactive, expired, or
// mismatched fact. The caller supplies a trusted current time for deterministic
// checking; client-provided times must not be used.
func (c Context) AuthorizeEnquiryCreation(at time.Time) (CreationAuthorization, error) {
	membership := c.membership
	if !c.actor.Authenticated || !validID(c.actor.ID) || !validID(c.activeOrganizationID) ||
		!validID(membership.ID) || !validID(membership.ActorID) || !validID(membership.OrganizationID) ||
		!membership.Active || membership.ActorID != c.actor.ID ||
		membership.OrganizationID != c.activeOrganizationID ||
		!withinValidity(at, membership.ValidFrom, membership.ValidUntil) {
		return CreationAuthorization{}, ErrUnauthorized
	}

	allowed := false
	for _, capability := range membership.Capabilities {
		if capability == CapabilityCreateEnquiry {
			allowed = true
			break
		}
	}
	if !allowed {
		return CreationAuthorization{}, ErrUnauthorized
	}

	return CreationAuthorization{
		actorID:        c.actor.ID,
		organizationID: c.activeOrganizationID,
		membershipID:   membership.ID,
		authorizedAt:   at.UTC(),
		validFrom:      membership.ValidFrom.UTC(),
		validUntil:     membership.ValidUntil.UTC(),
		issued:         true,
	}, nil
}

// Valid checks that this value was issued with complete, internally consistent
// creation facts. It does not refresh membership or authorize a later action.
func (a CreationAuthorization) Valid() bool {
	return a.issued && validID(a.actorID) && validID(a.organizationID) &&
		validID(a.membershipID) && withinValidity(a.authorizedAt, a.validFrom, a.validUntil)
}

func (a CreationAuthorization) ActorID() string         { return a.actorID }
func (a CreationAuthorization) OrganizationID() string  { return a.organizationID }
func (a CreationAuthorization) MembershipID() string    { return a.membershipID }
func (a CreationAuthorization) AuthorizedAt() time.Time { return a.authorizedAt }

func withinValidity(at, from, until time.Time) bool {
	return validInstant(at) && validInstant(from) && validInstant(until) &&
		from.Before(until) && !at.Before(from) && at.Before(until)
}

func validInstant(instant time.Time) bool {
	instant = instant.UTC()
	return !instant.IsZero() && instant.Year() >= 1 && instant.Year() <= 9999
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 128 || !asciiAlphanumeric(id[0]) {
		return false
	}
	for i := 1; i < len(id); i++ {
		if !asciiAlphanumeric(id[i]) && id[i] != '-' && id[i] != '_' {
			return false
		}
	}
	return true
}

func asciiAlphanumeric(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}
