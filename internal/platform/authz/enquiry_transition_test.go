package authz_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
)

func transitionInput(capability authz.Capability) authz.ContextInput {
	input := validContextInput()
	input.Actor.Human = true
	input.Membership.Capabilities = []authz.Capability{capability}
	input.TransitionGrant = authz.EnquiryTransitionGrant{
		ID: "grant-1", ActorID: input.Actor.ID, MembershipID: input.Membership.ID,
		OrganizationID: "org-1", EnquiryID: "enquiry-1", Capability: capability,
		Active: true, ValidFrom: authorizationTime.Add(-time.Hour), ValidUntil: authorizationTime.Add(time.Hour),
	}
	return input
}

func TestTransitionAuthorizationScopeAndAttribution(t *testing.T) {
	if authz.CapabilityReviewEnquiry != "enquiries.review" || authz.CapabilityQualifyEnquiry != "enquiries.qualify" {
		t.Fatal("canonical workflow capabilities changed")
	}
	for _, capability := range []authz.Capability{authz.CapabilityReviewEnquiry, authz.CapabilityQualifyEnquiry} {
		for _, identity := range []struct{ actor, membership, organization, enquiry, grant string }{
			{"actor-1", "membership-1", "org-1", "enquiry-1", "grant-1"},
			{"actor-2", "membership-2", "org-2", "enquiry-2", "grant-2"},
		} {
			input := transitionInput(capability)
			input.Actor.ID, input.Membership.ActorID = identity.actor, identity.actor
			input.Membership.ID = identity.membership
			input.ActiveOrganizationID, input.Membership.OrganizationID = identity.organization, identity.organization
			g := &input.TransitionGrant
			g.ID, g.ActorID, g.MembershipID = identity.grant, identity.actor, identity.membership
			g.OrganizationID, g.EnquiryID = identity.organization, identity.enquiry
			proof, err := authz.NewContext(input).AuthorizeEnquiryTransition(identity.enquiry, identity.organization, capability, authorizationTime)
			if err != nil || !proof.ValidFor(identity.enquiry, identity.organization, capability, authorizationTime) {
				t.Fatalf("valid transition denied: %v", err)
			}
			if proof.ActorID() != identity.actor || proof.MembershipID() != identity.membership || proof.OrganizationID() != identity.organization ||
				proof.GrantID() != identity.grant || proof.Capability() != capability || !proof.AuthorizedAt().Equal(authorizationTime) || proof.AuthorizedAt().Location() != time.UTC {
				t.Fatal("transition proof changed attribution")
			}
			otherCapability := authz.CapabilityReviewEnquiry
			if capability == otherCapability {
				otherCapability = authz.CapabilityQualifyEnquiry
			}
			if proof.ValidFor("other-enquiry", identity.organization, capability, authorizationTime) ||
				proof.ValidFor(identity.enquiry, "other-org", capability, authorizationTime) ||
				proof.ValidFor(identity.enquiry, identity.organization, otherCapability, authorizationTime) ||
				proof.ValidFor(identity.enquiry, identity.organization, capability, authorizationTime.Add(time.Nanosecond)) ||
				proof.ValidFor(identity.enquiry, identity.organization, capability, input.Membership.ValidUntil) {
				t.Fatal("proof accepted another resource, organization, action, instant, or expired use")
			}
		}
	}
}

func TestTransitionAuthorizationDenials(t *testing.T) {
	cases := []struct {
		name   string
		change func(*authz.ContextInput)
	}{
		{"missing actor", func(i *authz.ContextInput) { i.Actor = authz.Actor{} }},
		{"unauthenticated", func(i *authz.ContextInput) { i.Actor.Authenticated = false }},
		{"system or AI actor", func(i *authz.ContextInput) { i.Actor.Human = false }},
		{"missing organization", func(i *authz.ContextInput) { i.ActiveOrganizationID = "" }},
		{"malformed organization", func(i *authz.ContextInput) { i.ActiveOrganizationID = "org-1\n" }},
		{"missing membership", func(i *authz.ContextInput) { i.Membership = authz.Membership{} }},
		{"malformed membership", func(i *authz.ContextInput) { i.Membership.ID = "../membership" }},
		{"inactive membership", func(i *authz.ContextInput) { i.Membership.Active = false }},
		{"revoked membership", func(i *authz.ContextInput) { i.Membership.Revoked = true }},
		{"wrong membership actor", func(i *authz.ContextInput) { i.Membership.ActorID = "other-actor" }},
		{"wrong membership organization", func(i *authz.ContextInput) { i.Membership.OrganizationID = "other-org" }},
		{"expired membership", func(i *authz.ContextInput) { i.Membership.ValidUntil = authorizationTime }},
		{"premature membership", func(i *authz.ContextInput) { i.Membership.ValidFrom = authorizationTime.Add(time.Nanosecond) }},
		{"missing membership start", func(i *authz.ContextInput) { i.Membership.ValidFrom = time.Time{} }},
		{"missing membership end", func(i *authz.ContextInput) { i.Membership.ValidUntil = time.Time{} }},
		{"missing capability", func(i *authz.ContextInput) { i.Membership.Capabilities = nil }},
		{"creation only", func(i *authz.ContextInput) {
			i.Membership.Capabilities = []authz.Capability{authz.CapabilityCreateEnquiry}
		}},
		// Role administration is deferred. An administrative label/permission is
		// not the exact workflow capability and must not be treated as a bypass.
		{"administrator only", func(i *authz.ContextInput) {
			i.Membership.Capabilities = []authz.Capability{"organization.admin", "Organization access administrator"}
		}},
		{"wildcard", func(i *authz.ContextInput) { i.Membership.Capabilities = []authz.Capability{"enquiries.*", "*"} }},
		{"missing grant", func(i *authz.ContextInput) { i.TransitionGrant = authz.EnquiryTransitionGrant{} }},
		{"missing grant ID", func(i *authz.ContextInput) { i.TransitionGrant.ID = "" }},
		{"malformed grant ID", func(i *authz.ContextInput) { i.TransitionGrant.ID = "grant 1" }},
		{"inactive grant", func(i *authz.ContextInput) { i.TransitionGrant.Active = false }},
		{"revoked grant", func(i *authz.ContextInput) { i.TransitionGrant.Revoked = true }},
		{"grant actor mismatch", func(i *authz.ContextInput) { i.TransitionGrant.ActorID = "other-actor" }},
		{"grant membership mismatch", func(i *authz.ContextInput) { i.TransitionGrant.MembershipID = "other-membership" }},
		{"grant organization mismatch", func(i *authz.ContextInput) { i.TransitionGrant.OrganizationID = "other-org" }},
		{"grant enquiry mismatch", func(i *authz.ContextInput) { i.TransitionGrant.EnquiryID = "other-enquiry" }},
		{"grant action mismatch", func(i *authz.ContextInput) { i.TransitionGrant.Capability = authz.CapabilityCreateEnquiry }},
		{"expired grant", func(i *authz.ContextInput) { i.TransitionGrant.ValidUntil = authorizationTime }},
		{"premature grant", func(i *authz.ContextInput) { i.TransitionGrant.ValidFrom = authorizationTime.Add(time.Nanosecond) }},
		{"missing grant start", func(i *authz.ContextInput) { i.TransitionGrant.ValidFrom = time.Time{} }},
		{"missing grant end", func(i *authz.ContextInput) { i.TransitionGrant.ValidUntil = time.Time{} }},
		{"reversed grant bounds", func(i *authz.ContextInput) {
			i.TransitionGrant.ValidUntil = i.TransitionGrant.ValidFrom.Add(-time.Nanosecond)
		}},
		{"unrepresentable grant end", func(i *authz.ContextInput) {
			i.TransitionGrant.ValidUntil = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		}},
	}
	for _, capability := range []authz.Capability{authz.CapabilityReviewEnquiry, authz.CapabilityQualifyEnquiry} {
		for _, tc := range cases {
			t.Run(string(capability)+"/"+tc.name, func(t *testing.T) {
				input := transitionInput(capability)
				tc.change(&input)
				proof, err := authz.NewContext(input).AuthorizeEnquiryTransition("enquiry-1", "org-1", capability, authorizationTime)
				if err != authz.ErrTransitionUnauthorized || !reflect.DeepEqual(proof, authz.EnquiryTransitionAuthorization{}) {
					t.Fatalf("denial = (%v, %v); want safe error and no proof", proof, err)
				}
			})
		}
		input := transitionInput(capability)
		other := authz.CapabilityReviewEnquiry
		if capability == other {
			other = authz.CapabilityQualifyEnquiry
		}
		input.Membership.Capabilities = []authz.Capability{other}
		if _, err := authz.NewContext(input).AuthorizeEnquiryTransition("enquiry-1", "org-1", capability, authorizationTime); err != authz.ErrTransitionUnauthorized {
			t.Fatal("one workflow capability implied the other")
		}
		for _, requested := range []authz.Capability{"", "enquiries.*", authz.CapabilityCreateEnquiry, "ENQUIRIES.REVIEW", " enquiries.qualify "} {
			// Matching membership and grant entitlements must still not authorize
			// an unsupported transition action through this bounded interface.
			if _, err := authz.NewContext(transitionInput(requested)).AuthorizeEnquiryTransition("enquiry-1", "org-1", requested, authorizationTime); err != authz.ErrTransitionUnauthorized {
				t.Fatal("unsupported transition capability accepted")
			}
		}
	}
}

func TestTransitionAuthorizationTimeBoundariesAndSnapshots(t *testing.T) {
	input := transitionInput(authz.CapabilityReviewEnquiry)
	for _, tc := range []struct {
		name    string
		at      time.Time
		allowed bool
	}{
		{"inclusive start", input.Membership.ValidFrom, true},
		{"before expiry", input.Membership.ValidUntil.Add(-time.Nanosecond), true},
		{"exclusive expiry", input.Membership.ValidUntil, false},
		{"before start", input.Membership.ValidFrom.Add(-time.Nanosecond), false},
		{"zero time", time.Time{}, false},
		{"invalid time", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof, err := authz.NewContext(input).AuthorizeEnquiryTransition("enquiry-1", "org-1", authz.CapabilityReviewEnquiry, tc.at)
			if tc.allowed {
				if err != nil || !proof.ValidFor("enquiry-1", "org-1", authz.CapabilityReviewEnquiry, tc.at) {
					t.Fatalf("boundary denied: %v", err)
				}
			} else if err != authz.ErrTransitionUnauthorized || !reflect.DeepEqual(proof, authz.EnquiryTransitionAuthorization{}) {
				t.Fatal("invalid instant allowed")
			}
		})
	}
	context := authz.NewContext(input)
	input.Actor.Human = false
	input.Membership.Capabilities[0] = authz.CapabilityQualifyEnquiry
	input.TransitionGrant.Revoked = true
	proof, err := context.AuthorizeEnquiryTransition("enquiry-1", "org-1", authz.CapabilityReviewEnquiry, authorizationTime)
	if err != nil || !proof.ValidFor("enquiry-1", "org-1", authz.CapabilityReviewEnquiry, authorizationTime) {
		t.Fatal("caller changed context snapshot")
	}
	input = transitionInput(authz.CapabilityReviewEnquiry)
	input.Membership.Capabilities[0] = authz.CapabilityQualifyEnquiry
	context = authz.NewContext(input)
	input.Membership.Capabilities[0] = authz.CapabilityReviewEnquiry
	if _, err := context.AuthorizeEnquiryTransition("enquiry-1", "org-1", authz.CapabilityReviewEnquiry, authorizationTime); err != authz.ErrTransitionUnauthorized {
		t.Fatal("caller escalated snapshot")
	}
	var zero authz.EnquiryTransitionAuthorization
	if zero.ValidFor("enquiry-1", "org-1", authz.CapabilityReviewEnquiry, authorizationTime) {
		t.Fatal("zero proof allowed")
	}
	var empty authz.Context
	if _, err := empty.AuthorizeEnquiryTransition("enquiry-1", "org-1", authz.CapabilityReviewEnquiry, authorizationTime); err != authz.ErrTransitionUnauthorized {
		t.Fatal("zero context allowed")
	}
	creation := validContextInput()
	creation.Membership.Revoked = true
	if _, err := authz.NewContext(creation).AuthorizeEnquiryCreation(authorizationTime); err != authz.ErrUnauthorized {
		t.Fatal("revoked membership allowed creation")
	}
}
