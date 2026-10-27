package enquiries

import (
	"errors"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
)

const (
	StateUnderReview State = "Under review"
	StateQualified   State = "Qualified"
)

var (
	ErrInvalidTransition = errors.New("invalid enquiry transition")
	ErrVersionConflict   = errors.New("enquiry version conflict")
)

func (e Enquiry) AssigneeMembershipID() string { return e.assigneeMembershipID }
func (e Enquiry) Version() uint64              { return e.version }

// TransitionAudit omits enquiry input and contains detached, attributable facts.
// It must eventually be persisted atomically with the returned enquiry after
// checking current authority and stored version; it is not a durable audit log.
type TransitionAudit struct {
	Action                       string
	OrganizationID               string
	ActiveOrganizationID         string
	EnquiryID                    string
	PreviousState                State
	NewState                     State
	ActorID                      string
	MembershipID                 string
	GrantID                      string
	Capability                   authz.Capability
	PreviousAssigneeMembershipID string
	AssigneeMembershipID         string
	PreviousVersion              uint64
	Version                      uint64
	At                           time.Time
}

// TransitionResult is an all-or-nothing pair of independent values. A failure
// returns its zero value and never changes the receiver or earlier audit values.
type TransitionResult struct {
	Enquiry Enquiry
	Audit   TransitionAudit
}

func (e Enquiry) StartReview(authorization authz.EnquiryTransitionAuthorization, expectedVersion uint64, at time.Time) (TransitionResult, error) {
	return e.transition(authorization, expectedVersion, at, authz.CapabilityReviewEnquiry, StateNew, StateUnderReview, "enquiry.review_started")
}

func (e Enquiry) Qualify(authorization authz.EnquiryTransitionAuthorization, expectedVersion uint64, at time.Time) (TransitionResult, error) {
	return e.transition(authorization, expectedVersion, at, authz.CapabilityQualifyEnquiry, StateUnderReview, StateQualified, "enquiry.qualified")
}

func (e Enquiry) transition(authorization authz.EnquiryTransitionAuthorization, expectedVersion uint64, at time.Time, capability authz.Capability, from, to State, action string) (TransitionResult, error) {
	if !authorization.ValidFor(e.id, e.organizationID, capability, at) {
		return TransitionResult{}, authz.ErrTransitionUnauthorized
	}
	if e.version == 0 || expectedVersion != e.version {
		return TransitionResult{}, ErrVersionConflict
	}
	if e.state != from || at.Before(e.createdAt) || at.Before(e.lastChangedAt) {
		return TransitionResult{}, ErrInvalidTransition
	}
	if capability == authz.CapabilityReviewEnquiry && e.assigneeMembershipID != "" {
		return TransitionResult{}, ErrInvalidTransition
	}
	if capability == authz.CapabilityQualifyEnquiry && e.assigneeMembershipID != authorization.MembershipID() {
		return TransitionResult{}, authz.ErrTransitionUnauthorized
	}

	// No authoritative values change until every check has succeeded. This copy
	// publishes state and assignment together; persistence/CAS remain future work.
	next := e
	next.state = to
	if capability == authz.CapabilityReviewEnquiry {
		next.assigneeMembershipID = authorization.MembershipID()
	}
	next.version++
	next.lastChangedAt = at.UTC()
	audit := TransitionAudit{
		Action: action, OrganizationID: e.organizationID, ActiveOrganizationID: authorization.OrganizationID(),
		EnquiryID: e.id, PreviousState: e.state, NewState: next.state,
		ActorID: authorization.ActorID(), MembershipID: authorization.MembershipID(),
		GrantID: authorization.GrantID(), Capability: capability,
		PreviousAssigneeMembershipID: e.assigneeMembershipID, AssigneeMembershipID: next.assigneeMembershipID,
		PreviousVersion: e.version, Version: next.version, At: at.UTC(),
	}
	return TransitionResult{Enquiry: next, Audit: audit}, nil
}
