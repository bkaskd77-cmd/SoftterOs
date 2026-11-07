package authz_test

import (
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
)

func TestAssignedEnquiryReadPolicy(t *testing.T) {
	start := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	base := authz.ContextInput{
		Actor: authz.Actor{ID: "actor-read", Authenticated: true, Human: true}, ActiveOrganizationID: "org-read",
		Membership: authz.Membership{ID: "member-read", ActorID: "actor-read", OrganizationID: "org-read", Active: true,
			ValidFrom: start, ValidUntil: end, Capabilities: []authz.Capability{"enquiries.read"}},
	}
	for _, at := range []time.Time{start, end.Add(-time.Nanosecond)} {
		policy := authz.NewContext(base)
		if !policy.CanReadAssignedEnquiries(at) || !policy.CanReadAssignedEnquiry("org-read", "member-read", at) {
			t.Fatal("valid independently entitled assignee denied")
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*authz.ContextInput)
	}{
		{"unauthenticated", func(in *authz.ContextInput) { in.Actor.Authenticated = false }},
		{"nonhuman", func(in *authz.ContextInput) { in.Actor.Human = false }},
		{"no active organization", func(in *authz.ContextInput) { in.ActiveOrganizationID = "" }},
		{"wrong actor", func(in *authz.ContextInput) { in.Membership.ActorID = "actor-other" }},
		{"wrong organization", func(in *authz.ContextInput) { in.Membership.OrganizationID = "org-other" }},
		{"inactive", func(in *authz.ContextInput) { in.Membership.Active = false }},
		{"revoked", func(in *authz.ContextInput) { in.Membership.Revoked = true }},
		{"missing entitlement", func(in *authz.ContextInput) { in.Membership.Capabilities = nil }},
		{"write capabilities only", func(in *authz.ContextInput) {
			in.Membership.Capabilities = []authz.Capability{
				authz.CapabilityCreateEnquiry, authz.CapabilityReviewEnquiry, authz.CapabilityQualifyEnquiry,
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.change(&in)
			policy := authz.NewContext(in)
			if policy.CanReadAssignedEnquiries(start) || policy.CanReadAssignedEnquiry("org-read", "member-read", start) {
				t.Fatal("invalid or unrelated authority allowed an assigned read")
			}
		})
	}
	policy := authz.NewContext(base)
	for _, at := range []time.Time{start.Add(-time.Nanosecond), end} {
		if policy.CanReadAssignedEnquiries(at) || policy.CanReadAssignedEnquiry("org-read", "member-read", at) {
			t.Fatal("read permitted outside the membership interval")
		}
	}
	if policy.CanReadAssignedEnquiry("org-other", "member-read", start) ||
		policy.CanReadAssignedEnquiry("org-read", "member-other", start) ||
		policy.CanReadAssignedEnquiry("org-read", "", start) {
		t.Fatal("exact owner and current assignee are required")
	}
}
