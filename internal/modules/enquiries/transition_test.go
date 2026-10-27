package enquiries

import (
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
)

var domainTime = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func domainEnquiry(t *testing.T, id, organization string) Enquiry {
	t.Helper()
	context := authz.NewContext(authz.ContextInput{
		Actor: authz.Actor{ID: "creator", Authenticated: true}, ActiveOrganizationID: organization,
		Membership: authz.Membership{ID: "creator-membership", ActorID: "creator", OrganizationID: organization,
			Active: true, ValidFrom: domainTime.Add(-time.Hour), ValidUntil: domainTime.Add(time.Hour),
			Capabilities: []authz.Capability{authz.CapabilityCreateEnquiry}},
	})
	creation, err := context.AuthorizeEnquiryCreation(domainTime)
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(id, Input{ContactName: "Synthetic Contact", ContactEmail: "contact@example.com", Destination: "Norway", TravellerCount: 2, TravelStart: "2020-02-29", TravelEnd: "2020-03-02"}, creation)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func domainProof(t *testing.T, e Enquiry, capability authz.Capability, actor, membership string, at time.Time) authz.EnquiryTransitionAuthorization {
	t.Helper()
	context := authz.NewContext(authz.ContextInput{
		Actor: authz.Actor{ID: actor, Authenticated: true, Human: true}, ActiveOrganizationID: e.OrganizationID(),
		Membership: authz.Membership{ID: membership, ActorID: actor, OrganizationID: e.OrganizationID(),
			Active: true, ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour), Capabilities: []authz.Capability{capability}},
		TransitionGrant: authz.EnquiryTransitionGrant{ID: "grant-" + actor, ActorID: actor, MembershipID: membership,
			OrganizationID: e.OrganizationID(), EnquiryID: e.ID(), Capability: capability,
			Active: true, ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)},
	})
	proof, err := context.AuthorizeEnquiryTransition(e.ID(), e.OrganizationID(), capability, at)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestDomainReviewAndQualification(t *testing.T) {
	if StateUnderReview != "Under review" || StateQualified != "Qualified" {
		t.Fatal("canonical states changed")
	}
	for _, identity := range []struct{ actor, membership, organization, enquiry string }{
		{"actor-1", "membership-1", "org-1", "enquiry-1"},
		{"actor-2", "membership-2", "org-2", "enquiry-2"},
	} {
		t.Run(identity.actor, func(t *testing.T) {
			e := domainEnquiry(t, identity.enquiry, identity.organization)
			original, creationAudit := e, e.CreationAudit()
			at := domainTime.Add(time.Minute)
			proof := domainProof(t, e, authz.CapabilityReviewEnquiry, identity.actor, identity.membership, at)
			review, err := e.StartReview(proof, 1, at)
			if err != nil {
				t.Fatal(err)
			}
			if e != original || e.Version() != 1 || e.AssigneeMembershipID() != "" || review.Enquiry.State() != StateUnderReview ||
				review.Enquiry.AssigneeMembershipID() != identity.membership || review.Enquiry.Version() != 2 {
				t.Fatal("review was not an atomic independent state/assignment result")
			}
			want := TransitionAudit{
				Action: "enquiry.review_started", OrganizationID: identity.organization, ActiveOrganizationID: identity.organization,
				EnquiryID: identity.enquiry, PreviousState: StateNew, NewState: StateUnderReview,
				ActorID: identity.actor, MembershipID: identity.membership, GrantID: "grant-" + identity.actor,
				Capability: authz.CapabilityReviewEnquiry, AssigneeMembershipID: identity.membership,
				PreviousVersion: 1, Version: 2, At: at,
			}
			if review.Audit != want {
				t.Fatalf("review audit = %+v; want %+v", review.Audit, want)
			}
			reviewSnapshot := review
			at = at.Add(time.Minute)
			proof = domainProof(t, review.Enquiry, authz.CapabilityQualifyEnquiry, identity.actor, identity.membership, at)
			qualified, err := review.Enquiry.Qualify(proof, 2, at)
			if err != nil {
				t.Fatal(err)
			}
			want.Action, want.PreviousState, want.NewState = "enquiry.qualified", StateUnderReview, StateQualified
			want.Capability, want.PreviousAssigneeMembershipID = authz.CapabilityQualifyEnquiry, identity.membership
			want.PreviousVersion, want.Version, want.At = 2, 3, at
			if qualified.Audit != want || qualified.Enquiry.State() != StateQualified || qualified.Enquiry.Version() != 3 || qualified.Enquiry.AssigneeMembershipID() != identity.membership {
				t.Fatal("incorrect qualification state, assignment, or audit attribution")
			}
			if review != reviewSnapshot || qualified.Enquiry.CreationAudit() != creationAudit || qualified.Enquiry.Input() != original.Input() || qualified.Enquiry.CreatedBy() != "creator" {
				t.Fatal("workflow changed prior values, creator, historical dates, or creation audit")
			}
			copyOfResult := qualified
			copyOfResult.Audit.ActorID, copyOfResult.Audit.AssigneeMembershipID = "changed", "changed"
			inputCopy := copyOfResult.Enquiry.Input()
			inputCopy.ContactName = "Changed"
			if qualified.Audit != want || qualified.Enquiry.AssigneeMembershipID() != identity.membership || qualified.Enquiry.Input() != original.Input() {
				t.Fatal("returned values mutated authoritative state or audit")
			}
		})
	}
}

func TestDomainTransitionDenialsPreserveStateAndAudit(t *testing.T) {
	at := domainTime.Add(time.Minute)
	initial := domainEnquiry(t, "enquiry-1", "org-1")
	review, err := initial.StartReview(domainProof(t, initial, authz.CapabilityReviewEnquiry, "actor-1", "membership-1", at), 1, at)
	if err != nil {
		t.Fatal(err)
	}
	qualifyAt := at.Add(time.Minute)
	qualified, err := review.Enquiry.Qualify(domainProof(t, review.Enquiry, authz.CapabilityQualifyEnquiry, "actor-1", "membership-1", qualifyAt), 2, qualifyAt)
	if err != nil {
		t.Fatal(err)
	}
	priorReview, priorQualified := review, qualified
	cases := []struct {
		name              string
		enquiry           Enquiry
		qualify           bool
		change            func(*Enquiry)
		actor, membership string
		version           uint64
		want              error
	}{
		{"direct qualification", initial, true, nil, "actor-1", "membership-1", 1, ErrInvalidTransition},
		{"repeat review", review.Enquiry, false, nil, "actor-1", "membership-1", 2, ErrInvalidTransition},
		{"repeat qualification", qualified.Enquiry, true, nil, "actor-1", "membership-1", 3, ErrInvalidTransition},
		{"review qualified enquiry", qualified.Enquiry, false, nil, "actor-1", "membership-1", 3, ErrInvalidTransition},
		{"invalid state", initial, false, func(e *Enquiry) { e.state = "Spam" }, "actor-1", "membership-1", 1, ErrInvalidTransition},
		{"empty state", initial, false, func(e *Enquiry) { e.state = "" }, "actor-1", "membership-1", 1, ErrInvalidTransition},
		{"already assigned New", initial, false, func(e *Enquiry) { e.assigneeMembershipID = "other-membership" }, "actor-1", "membership-1", 1, ErrInvalidTransition},
		{"missing assignee", review.Enquiry, true, func(e *Enquiry) { e.assigneeMembershipID = "" }, "actor-1", "membership-1", 2, authz.ErrTransitionUnauthorized},
		{"same actor different membership", review.Enquiry, true, nil, "actor-1", "membership-2", 2, authz.ErrTransitionUnauthorized},
		{"different assignee", review.Enquiry, true, nil, "actor-2", "membership-2", 2, authz.ErrTransitionUnauthorized},
		{"stale expected version", review.Enquiry, true, nil, "actor-1", "membership-1", 1, ErrVersionConflict},
		{"zero expected version", initial, false, nil, "actor-1", "membership-1", 0, ErrVersionConflict},
		{"invalid stored version", initial, false, func(e *Enquiry) { e.version = 0 }, "actor-1", "membership-1", 0, ErrVersionConflict},
		{"before creation", initial, false, func(e *Enquiry) { e.createdAt = qualifyAt.Add(time.Hour) }, "actor-1", "membership-1", 1, ErrInvalidTransition},
		{"before previous change", review.Enquiry, true, func(e *Enquiry) { e.lastChangedAt = qualifyAt.Add(time.Hour) }, "actor-1", "membership-1", 2, ErrInvalidTransition},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.enquiry
			if tc.change != nil {
				tc.change(&e)
			}
			before, beforeCreationAudit := e, e.CreationAudit()
			capability := authz.CapabilityReviewEnquiry
			if tc.qualify {
				capability = authz.CapabilityQualifyEnquiry
			}
			proof := domainProof(t, e, capability, tc.actor, tc.membership, qualifyAt)
			var result TransitionResult
			var err error
			if tc.qualify {
				result, err = e.Qualify(proof, tc.version, qualifyAt)
			} else {
				result, err = e.StartReview(proof, tc.version, qualifyAt)
			}
			if err != tc.want || result != (TransitionResult{}) {
				t.Fatalf("got result=%+v error=%v; want zero result and %v", result, err, tc.want)
			}
			if e != before || e.CreationAudit() != beforeCreationAudit || review != priorReview || qualified != priorQualified {
				t.Fatal("denial changed state, assignment, input, or prior audit")
			}
		})
	}
}

func TestDomainRejectsWrongOrStaleProofBeforeStateValidation(t *testing.T) {
	e := domainEnquiry(t, "enquiry-1", "org-1")
	at := domainTime.Add(time.Minute)
	otherEnquiry := domainEnquiry(t, "enquiry-2", "org-1")
	otherOrganization := domainEnquiry(t, "enquiry-1", "org-2")
	for _, tc := range []struct {
		name  string
		proof authz.EnquiryTransitionAuthorization
		at    time.Time
	}{
		{"zero", authz.EnquiryTransitionAuthorization{}, at},
		{"wrong enquiry", domainProof(t, otherEnquiry, authz.CapabilityReviewEnquiry, "actor-1", "membership-1", at), at},
		{"wrong organization", domainProof(t, otherOrganization, authz.CapabilityReviewEnquiry, "actor-1", "membership-1", at), at},
		{"wrong action", domainProof(t, e, authz.CapabilityQualifyEnquiry, "actor-1", "membership-1", at), at},
		{"expired proof", domainProof(t, e, authz.CapabilityReviewEnquiry, "actor-1", "membership-1", at), at.Add(time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, beforeAudit := e, e.CreationAudit()
			result, err := e.StartReview(tc.proof, 0, tc.at)
			if err != authz.ErrTransitionUnauthorized || result != (TransitionResult{}) || e != before || e.CreationAudit() != beforeAudit {
				t.Fatal("invalid proof was accepted or disclosed state/version validation")
			}
		})
	}
	var empty Enquiry
	result, err := empty.StartReview(domainProof(t, e, authz.CapabilityReviewEnquiry, "actor-1", "membership-1", at), 0, at)
	if err != authz.ErrTransitionUnauthorized || result != (TransitionResult{}) {
		t.Fatal("zero enquiry accepted")
	}
}
