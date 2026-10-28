package application_test

import (
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries/application"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
)

func workflowEnquiry(t *testing.T, id, organization string) enquiries.Enquiry {
	t.Helper()
	facts := validContextInput()
	facts.ActiveOrganizationID, facts.Membership.OrganizationID = organization, organization
	creator, err := application.NewCreator(func() time.Time { return creationTime }, func() (string, error) { return id, nil })
	if err != nil {
		t.Fatal(err)
	}
	input := validInput()
	input.TravelStart, input.TravelEnd = "2020-02-29", "2020-03-02"
	input.ContactName, input.Destination = "caller-actor", "caller-organization"
	result, err := creator.Create(authz.NewContext(facts), input)
	if err != nil {
		t.Fatal(err)
	}
	return result.Enquiry
}

func workflowFacts(e enquiries.Enquiry, capability authz.Capability, actor, membership string, at time.Time) authz.ContextInput {
	return authz.ContextInput{
		Actor: authz.Actor{ID: actor, Authenticated: true, Human: true}, ActiveOrganizationID: e.OrganizationID(),
		Membership: authz.Membership{ID: membership, ActorID: actor, OrganizationID: e.OrganizationID(), Active: true,
			ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour), Capabilities: []authz.Capability{capability}},
		TransitionGrant: authz.EnquiryTransitionGrant{ID: "grant-" + actor, ActorID: actor, MembershipID: membership,
			OrganizationID: e.OrganizationID(), EnquiryID: e.ID(), Capability: capability, Active: true,
			ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)},
	}
}

func TestWorkflowReviewAndQualificationAttribution(t *testing.T) {
	for _, identity := range []struct{ actor, membership, organization, enquiry string }{
		{"actor-2", "membership-2", "org-1", "enquiry-1"},
		{"actor-3", "membership-3", "org-2", "enquiry-2"},
	} {
		t.Run(identity.actor, func(t *testing.T) {
			e := workflowEnquiry(t, identity.enquiry, identity.organization)
			original, creationAudit := e, e.CreationAudit()
			at := creationTime.Add(time.Minute)
			calls := 0
			workflow, err := application.NewWorkflow(func() time.Time { calls++; return at })
			if err != nil {
				t.Fatal(err)
			}
			facts := workflowFacts(e, authz.CapabilityReviewEnquiry, identity.actor, identity.membership, at)
			review, err := workflow.StartReview(authz.NewContext(facts), e, 1)
			if err != nil {
				t.Fatal(err)
			}
			want := enquiries.TransitionAudit{
				Action: "enquiry.review_started", OrganizationID: identity.organization, ActiveOrganizationID: identity.organization,
				EnquiryID: identity.enquiry, PreviousState: enquiries.StateNew, NewState: enquiries.StateUnderReview,
				ActorID: identity.actor, MembershipID: identity.membership, GrantID: "grant-" + identity.actor,
				Capability: authz.CapabilityReviewEnquiry, AssigneeMembershipID: identity.membership, PreviousVersion: 1, Version: 2, At: at,
			}
			if review.Audit != want || review.Enquiry.State() != enquiries.StateUnderReview || review.Enquiry.AssigneeMembershipID() != identity.membership || review.Enquiry.Version() != 2 || e != original {
				t.Fatal("incorrect atomic review result or attribution")
			}
			priorReview := review
			at = at.Add(time.Minute)
			facts = workflowFacts(review.Enquiry, authz.CapabilityQualifyEnquiry, identity.actor, identity.membership, at)
			qualified, err := workflow.Qualify(authz.NewContext(facts), review.Enquiry, 2)
			if err != nil {
				t.Fatal(err)
			}
			want.Action, want.PreviousState, want.NewState = "enquiry.qualified", enquiries.StateUnderReview, enquiries.StateQualified
			want.Capability, want.PreviousAssigneeMembershipID = authz.CapabilityQualifyEnquiry, identity.membership
			want.PreviousVersion, want.Version, want.At = 2, 3, at
			if qualified.Audit != want || qualified.Enquiry.State() != enquiries.StateQualified || qualified.Enquiry.AssigneeMembershipID() != identity.membership || qualified.Enquiry.Version() != 3 || calls != 2 {
				t.Fatal("incorrect qualification result, attribution, or clock use")
			}
			if review != priorReview || qualified.Enquiry.CreationAudit() != creationAudit || qualified.Enquiry.Input() != original.Input() || qualified.Enquiry.CreatedBy() != "actor-1" {
				t.Fatal("workflow overwrote creator, historical input, or earlier audit")
			}
			copyOfResult := qualified
			copyOfResult.Audit.MembershipID = "caller-membership"
			copyOfResult.Audit.OrganizationID = "caller-organization"
			if qualified.Audit != want || qualified.Enquiry.OrganizationID() != identity.organization || qualified.Enquiry.AssigneeMembershipID() != identity.membership {
				t.Fatal("audit mutation changed authoritative facts")
			}
		})
	}
}

func TestWorkflowAuthorizationDenialsLeaveEveryValueUnchanged(t *testing.T) {
	at := creationTime.Add(time.Minute)
	workflow, err := application.NewWorkflow(func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	initial := workflowEnquiry(t, "enquiry-1", "org-1")
	review, err := workflow.StartReview(authz.NewContext(workflowFacts(initial, authz.CapabilityReviewEnquiry, "actor-2", "membership-2", at)), initial, 1)
	if err != nil {
		t.Fatal(err)
	}
	priorReview := review
	cases := []struct {
		name   string
		change func(*authz.ContextInput)
	}{
		{"missing actor", func(i *authz.ContextInput) { i.Actor = authz.Actor{} }},
		{"unauthenticated", func(i *authz.ContextInput) { i.Actor.Authenticated = false }},
		{"AI actor", func(i *authz.ContextInput) { i.Actor.Human = false }},
		{"missing active organization", func(i *authz.ContextInput) { i.ActiveOrganizationID = "" }},
		{"inactive membership", func(i *authz.ContextInput) { i.Membership.Active = false }},
		{"revoked membership", func(i *authz.ContextInput) { i.Membership.Revoked = true }},
		{"expired membership", func(i *authz.ContextInput) { i.Membership.ValidUntil = at }},
		{"premature membership", func(i *authz.ContextInput) { i.Membership.ValidFrom = at.Add(time.Nanosecond) }},
		{"mismatched membership actor", func(i *authz.ContextInput) { i.Membership.ActorID = "other-actor" }},
		{"mismatched membership organization", func(i *authz.ContextInput) { i.Membership.OrganizationID = "other-org" }},
		{"missing capability", func(i *authz.ContextInput) { i.Membership.Capabilities = nil }},
		{"wrong capability", func(i *authz.ContextInput) {
			i.Membership.Capabilities = []authz.Capability{authz.CapabilityCreateEnquiry}
		}},
		{"other workflow capability", func(i *authz.ContextInput) {
			if i.TransitionGrant.Capability == authz.CapabilityReviewEnquiry {
				i.Membership.Capabilities = []authz.Capability{authz.CapabilityQualifyEnquiry}
			} else {
				i.Membership.Capabilities = []authz.Capability{authz.CapabilityReviewEnquiry}
			}
		}},
		{"administrative label alone", func(i *authz.ContextInput) {
			i.Membership.Capabilities = []authz.Capability{"organization.admin", "Organization access administrator"}
		}},
		{"missing grant", func(i *authz.ContextInput) { i.TransitionGrant = authz.EnquiryTransitionGrant{} }},
		{"inactive grant", func(i *authz.ContextInput) { i.TransitionGrant.Active = false }},
		{"revoked grant", func(i *authz.ContextInput) { i.TransitionGrant.Revoked = true }},
		{"expired grant", func(i *authz.ContextInput) { i.TransitionGrant.ValidUntil = at }},
		{"premature grant", func(i *authz.ContextInput) { i.TransitionGrant.ValidFrom = at.Add(time.Nanosecond) }},
		{"mismatched grant actor", func(i *authz.ContextInput) { i.TransitionGrant.ActorID = "other-actor" }},
		{"mismatched grant membership", func(i *authz.ContextInput) { i.TransitionGrant.MembershipID = "other-membership" }},
		{"mismatched grant organization", func(i *authz.ContextInput) { i.TransitionGrant.OrganizationID = "other-org" }},
		{"mismatched grant enquiry", func(i *authz.ContextInput) { i.TransitionGrant.EnquiryID = "other-enquiry" }},
		{"mismatched grant action", func(i *authz.ContextInput) { i.TransitionGrant.Capability = authz.CapabilityCreateEnquiry }},
		{"coherent other tenant", func(i *authz.ContextInput) {
			i.ActiveOrganizationID, i.Membership.OrganizationID, i.TransitionGrant.OrganizationID = "org-2", "org-2", "org-2"
		}},
		{"resource organization differs from active organization", func(i *authz.ContextInput) {
			// Leave the org-1 grant/enquiry, exact assignee, action, state and
			// version valid so only the resource-to-active-organization guard denies.
			i.ActiveOrganizationID, i.Membership.OrganizationID = "org-2", "org-2"
		}},
	}
	for _, qualifying := range []bool{false, true} {
		for _, tc := range cases {
			name := "review/" + tc.name
			e, capability := initial, authz.CapabilityReviewEnquiry
			if qualifying {
				e, capability, name = review.Enquiry, authz.CapabilityQualifyEnquiry, "qualify/"+tc.name
			}
			t.Run(name, func(t *testing.T) {
				before, beforeAudit := e, e.CreationAudit()
				facts := workflowFacts(e, capability, "actor-2", "membership-2", at)
				tc.change(&facts)
				var result enquiries.TransitionResult
				var err error
				if qualifying {
					result, err = workflow.Qualify(authz.NewContext(facts), e, e.Version())
				} else {
					result, err = workflow.StartReview(authz.NewContext(facts), e, e.Version())
				}
				if err != authz.ErrTransitionUnauthorized || result != (enquiries.TransitionResult{}) {
					t.Fatalf("denial returned result=%+v err=%v", result, err)
				}
				if e != before || e.CreationAudit() != beforeAudit || review != priorReview {
					t.Fatal("denied action changed enquiry or prior success audit")
				}
			})
		}
	}
	for _, identity := range []struct{ actor, membership string }{{"actor-2", "other-membership"}, {"actor-3", "membership-3"}} {
		facts := workflowFacts(review.Enquiry, authz.CapabilityQualifyEnquiry, identity.actor, identity.membership, at)
		result, err := workflow.Qualify(authz.NewContext(facts), review.Enquiry, review.Enquiry.Version())
		if err != authz.ErrTransitionUnauthorized || result != (enquiries.TransitionResult{}) || review != priorReview {
			t.Fatal("non-assignee qualified or changed prior facts")
		}
	}
}

func TestWorkflowInvalidTransitionsAndConfiguration(t *testing.T) {
	at := creationTime.Add(time.Minute)
	workflow, err := application.NewWorkflow(func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	initial := workflowEnquiry(t, "enquiry-1", "org-1")
	review, err := workflow.StartReview(authz.NewContext(workflowFacts(initial, authz.CapabilityReviewEnquiry, "actor-2", "membership-2", at)), initial, 1)
	if err != nil {
		t.Fatal(err)
	}
	qualified, err := workflow.Qualify(authz.NewContext(workflowFacts(review.Enquiry, authz.CapabilityQualifyEnquiry, "actor-2", "membership-2", at)), review.Enquiry, 2)
	if err != nil {
		t.Fatal(err)
	}
	priorReview, priorQualified := review, qualified
	for _, tc := range []struct {
		name    string
		e       enquiries.Enquiry
		qualify bool
		version uint64
		want    error
	}{
		{"direct qualification", initial, true, 1, enquiries.ErrInvalidTransition},
		{"repeated review", review.Enquiry, false, 2, enquiries.ErrInvalidTransition},
		{"repeated qualification", qualified.Enquiry, true, 3, enquiries.ErrInvalidTransition},
		{"review after qualification", qualified.Enquiry, false, 3, enquiries.ErrInvalidTransition},
		{"stale version", review.Enquiry, true, 1, enquiries.ErrVersionConflict},
		{"zero version", initial, false, 0, enquiries.ErrVersionConflict},
		{"zero enquiry", enquiries.Enquiry{}, false, 0, authz.ErrTransitionUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, beforeAudit := tc.e, tc.e.CreationAudit()
			capability := authz.CapabilityReviewEnquiry
			if tc.qualify {
				capability = authz.CapabilityQualifyEnquiry
			}
			facts := workflowFacts(tc.e, capability, "actor-2", "membership-2", at)
			var result enquiries.TransitionResult
			var err error
			if tc.qualify {
				result, err = workflow.Qualify(authz.NewContext(facts), tc.e, tc.version)
			} else {
				result, err = workflow.StartReview(authz.NewContext(facts), tc.e, tc.version)
			}
			if err != tc.want || result != (enquiries.TransitionResult{}) || tc.e != before || tc.e.CreationAudit() != beforeAudit || review != priorReview || qualified != priorQualified {
				t.Fatalf("invalid transition result=%+v err=%v; want %v and unchanged prior values", result, err, tc.want)
			}
		})
	}
	if _, err := application.NewWorkflow(nil); err != application.ErrWorkflowConfiguration {
		t.Fatal("nil clock accepted")
	}
	var zero application.Workflow
	facts := workflowFacts(initial, authz.CapabilityReviewEnquiry, "actor-2", "membership-2", at)
	for _, call := range []func() (enquiries.TransitionResult, error){
		func() (enquiries.TransitionResult, error) {
			return zero.StartReview(authz.NewContext(facts), initial, 1)
		},
		func() (enquiries.TransitionResult, error) { return zero.Qualify(authz.NewContext(facts), initial, 1) },
	} {
		result, err := call()
		if err != application.ErrWorkflowConfiguration || result != (enquiries.TransitionResult{}) {
			t.Fatal("zero workflow did not fail safely")
		}
	}
	invalidClock, err := application.NewWorkflow(func() time.Time { return time.Time{} })
	if err != nil {
		t.Fatal(err)
	}
	result, err := invalidClock.StartReview(authz.NewContext(facts), initial, 1)
	if err != authz.ErrTransitionUnauthorized || result != (enquiries.TransitionResult{}) {
		t.Fatal("invalid clock accepted")
	}
}
