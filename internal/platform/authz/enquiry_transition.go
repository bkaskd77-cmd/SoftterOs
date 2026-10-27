package authz

import (
	"errors"
	"time"
)

const (
	CapabilityReviewEnquiry  Capability = "enquiries.review"
	CapabilityQualifyEnquiry Capability = "enquiries.qualify"
)

var ErrTransitionUnauthorized = errors.New("not authorized to transition enquiry")

// EnquiryTransitionGrant is a direct, single-enquiry/action entitlement supplied
// only by a trusted adapter after resolving organization, purpose and field
// restrictions. It is not a collaboration/delegation grant or a client request.
// ValidFrom is inclusive and ValidUntil exclusive. No role or wildcard bypass
// exists. Current facts must be loaded for every operation, including revocation.
type EnquiryTransitionGrant struct {
	ID             string
	ActorID        string
	MembershipID   string
	OrganizationID string
	EnquiryID      string
	Capability     Capability
	Active         bool
	Revoked        bool
	ValidFrom      time.Time
	ValidUntil     time.Time
}

// EnquiryTransitionAuthorization is an immutable, resource/action-bound proof
// for one action instant. Its zero value denies; it is not a reusable session.
type EnquiryTransitionAuthorization struct {
	context        Context
	enquiryID      string
	organizationID string
	capability     Capability
	authorizedAt   time.Time
	issued         bool
}

// AuthorizeEnquiryTransition requires authoritative resource identifiers, fresh
// verified context and a trusted current clock, never enquiry input claims.
func (c Context) AuthorizeEnquiryTransition(enquiryID, organizationID string, capability Capability, at time.Time) (EnquiryTransitionAuthorization, error) {
	if !c.canTransition(enquiryID, organizationID, capability, at) {
		return EnquiryTransitionAuthorization{}, ErrTransitionUnauthorized
	}
	return EnquiryTransitionAuthorization{
		context: c, enquiryID: enquiryID, organizationID: organizationID,
		capability: capability, authorizedAt: at.UTC(), issued: true,
	}, nil
}

func (c Context) canTransition(enquiryID, organizationID string, capability Capability, at time.Time) bool {
	if capability != CapabilityReviewEnquiry && capability != CapabilityQualifyEnquiry {
		return false
	}
	if !c.validMembership(at) || !c.actor.Human || !c.hasCapability(capability) ||
		!validID(enquiryID) || !validID(organizationID) || organizationID != c.activeOrganizationID {
		return false
	}
	g := c.transitionGrant
	return validID(g.ID) && g.Active && !g.Revoked &&
		g.ActorID == c.actor.ID && g.MembershipID == c.membership.ID &&
		g.OrganizationID == organizationID && g.EnquiryID == enquiryID && g.Capability == capability &&
		withinValidity(at, g.ValidFrom, g.ValidUntil)
}

// ValidFor rechecks the proof's exact resource, action and action instant as well
// as membership/grant validity. at must be the trusted operation time. A later
// operation must obtain a fresh proof; this does not query an external policy store.
func (a EnquiryTransitionAuthorization) ValidFor(enquiryID, organizationID string, capability Capability, at time.Time) bool {
	return a.issued && a.enquiryID == enquiryID && a.organizationID == organizationID &&
		a.capability == capability && a.authorizedAt.Equal(at) &&
		a.context.canTransition(enquiryID, organizationID, capability, at)
}

func (a EnquiryTransitionAuthorization) ActorID() string         { return a.context.actor.ID }
func (a EnquiryTransitionAuthorization) OrganizationID() string  { return a.organizationID }
func (a EnquiryTransitionAuthorization) MembershipID() string    { return a.context.membership.ID }
func (a EnquiryTransitionAuthorization) GrantID() string         { return a.context.transitionGrant.ID }
func (a EnquiryTransitionAuthorization) Capability() Capability  { return a.capability }
func (a EnquiryTransitionAuthorization) AuthorizedAt() time.Time { return a.authorizedAt }
