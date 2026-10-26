package authz_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
)

var authorizationTime = time.Date(2026, time.October, 26, 12, 0, 0, 0, time.UTC)

func validContextInput() authz.ContextInput {
	return authz.ContextInput{
		Actor:                authz.Actor{ID: "actor-1", Authenticated: true},
		ActiveOrganizationID: "org-1",
		Membership: authz.Membership{
			ID:             "membership-1",
			ActorID:        "actor-1",
			OrganizationID: "org-1",
			Active:         true,
			ValidFrom:      authorizationTime.Add(-time.Hour),
			ValidUntil:     authorizationTime.Add(time.Hour),
			Capabilities:   []authz.Capability{authz.CapabilityCreateEnquiry},
		},
	}
}

func TestAuthorizeEnquiryCreation(t *testing.T) {
	input := validContextInput()
	authorization, err := authz.NewContext(input).AuthorizeEnquiryCreation(authorizationTime)
	if err != nil {
		t.Fatalf("authorized creation failed: %v", err)
	}
	if !authorization.Valid() {
		t.Fatal("successful authorization must be valid")
	}
	if authorization.ActorID() != input.Actor.ID ||
		authorization.OrganizationID() != input.ActiveOrganizationID ||
		authorization.MembershipID() != input.Membership.ID ||
		!authorization.AuthorizedAt().Equal(authorizationTime) {
		t.Fatal("authorization must retain actor, organization, membership, and time")
	}
	if authz.CapabilityCreateEnquiry != "enquiries.create" {
		t.Fatal("canonical enquiry creation capability changed")
	}
}

func TestAuthorizeEnquiryCreationDenials(t *testing.T) {
	tests := []struct {
		name   string
		change func(*authz.ContextInput)
	}{
		{"missing actor", func(in *authz.ContextInput) { in.Actor = authz.Actor{} }},
		{"unauthenticated actor", func(in *authz.ContextInput) { in.Actor.Authenticated = false }},
		{"missing actor ID", func(in *authz.ContextInput) { in.Actor.ID = "" }},
		{"malformed actor", func(in *authz.ContextInput) { in.Actor.ID = "actor 1" }},
		{"matching malformed actor identities", func(in *authz.ContextInput) {
			in.Actor.ID = "actor 1"
			in.Membership.ActorID = in.Actor.ID
		}},
		{"missing organization", func(in *authz.ContextInput) { in.ActiveOrganizationID = "" }},
		{"malformed organization", func(in *authz.ContextInput) { in.ActiveOrganizationID = "org-1\n" }},
		{"matching malformed organizations", func(in *authz.ContextInput) {
			in.ActiveOrganizationID = "org-1\n"
			in.Membership.OrganizationID = in.ActiveOrganizationID
		}},
		{"missing membership", func(in *authz.ContextInput) { in.Membership = authz.Membership{} }},
		{"missing membership ID", func(in *authz.ContextInput) { in.Membership.ID = "" }},
		{"malformed membership ID", func(in *authz.ContextInput) { in.Membership.ID = "../membership" }},
		{"inactive membership", func(in *authz.ContextInput) { in.Membership.Active = false }},
		{"missing membership actor", func(in *authz.ContextInput) { in.Membership.ActorID = "" }},
		{"missing membership organization", func(in *authz.ContextInput) { in.Membership.OrganizationID = "" }},
		{"wrong membership actor", func(in *authz.ContextInput) { in.Membership.ActorID = "actor-2" }},
		{"cross organization", func(in *authz.ContextInput) { in.Membership.OrganizationID = "org-2" }},
		{"switched active organization", func(in *authz.ContextInput) { in.ActiveOrganizationID = "org-2" }},
		{"missing capabilities", func(in *authz.ContextInput) { in.Membership.Capabilities = nil }},
		{"wrong capability", func(in *authz.ContextInput) { in.Membership.Capabilities = []authz.Capability{"enquiries.read"} }},
		{"capability case mismatch", func(in *authz.ContextInput) { in.Membership.Capabilities = []authz.Capability{"ENQUIRIES.CREATE"} }},
		{"capability suffix", func(in *authz.ContextInput) { in.Membership.Capabilities = []authz.Capability{"enquiries.create.any"} }},
		{"capability whitespace", func(in *authz.ContextInput) { in.Membership.Capabilities = []authz.Capability{" enquiries.create "} }},
		{"missing valid from", func(in *authz.ContextInput) { in.Membership.ValidFrom = time.Time{} }},
		{"missing valid until", func(in *authz.ContextInput) { in.Membership.ValidUntil = time.Time{} }},
		{"not yet valid", func(in *authz.ContextInput) { in.Membership.ValidFrom = authorizationTime.Add(time.Nanosecond) }},
		{"expired", func(in *authz.ContextInput) { in.Membership.ValidUntil = authorizationTime.Add(-time.Nanosecond) }},
		{"at expiry", func(in *authz.ContextInput) { in.Membership.ValidUntil = authorizationTime }},
		{"empty validity interval", func(in *authz.ContextInput) { in.Membership.ValidUntil = in.Membership.ValidFrom }},
		{"reversed validity interval", func(in *authz.ContextInput) { in.Membership.ValidUntil = in.Membership.ValidFrom.Add(-time.Second) }},
		{"unrepresentable validity start", func(in *authz.ContextInput) { in.Membership.ValidFrom = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"unrepresentable validity end", func(in *authz.ContextInput) { in.Membership.ValidUntil = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validContextInput()
			test.change(&input)
			authorization, err := authz.NewContext(input).AuthorizeEnquiryCreation(authorizationTime)
			if !errors.Is(err, authz.ErrUnauthorized) {
				t.Fatalf("got %v, want ErrUnauthorized", err)
			}
			if authorization != (authz.CreationAuthorization{}) || authorization.Valid() {
				t.Fatal("denial must return no authorization facts")
			}
		})
	}
}

func TestAuthorizationIdentifierBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		valid bool
	}{
		{"short", "A", true},
		{"allowed characters", "A0_z-Z9", true},
		{"maximum length", strings.Repeat("a", 128), true},
		{"too long", strings.Repeat("a", 129), false},
		{"leading hyphen", "-id", false},
		{"leading underscore", "_id", false},
		{"space", "a b", false},
		{"control", "a\x00b", false},
		{"unicode", "organisasjon-ø", false},
		{"path separator", "a/b", false},
		{"dot", "a.b", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validContextInput()
			input.Actor.ID = test.id
			input.Membership.ActorID = test.id
			input.ActiveOrganizationID = test.id
			input.Membership.OrganizationID = test.id
			input.Membership.ID = test.id
			authorization, err := authz.NewContext(input).AuthorizeEnquiryCreation(authorizationTime)
			if test.valid {
				if err != nil || !authorization.Valid() {
					t.Fatalf("valid identifier denied: %v", err)
				}
			} else if !errors.Is(err, authz.ErrUnauthorized) || authorization.Valid() {
				t.Fatalf("invalid identifier authorized: %v", err)
			}
		})
	}
}

func TestAuthorizationTimeBoundaries(t *testing.T) {
	input := validContextInput()
	tests := []struct {
		name  string
		at    time.Time
		valid bool
	}{
		{"start included", input.Membership.ValidFrom, true},
		{"just before expiry", input.Membership.ValidUntil.Add(-time.Nanosecond), true},
		{"expiry excluded", input.Membership.ValidUntil, false},
		{"zero time", time.Time{}, false},
		{"invalid year", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), false},
		{"same instant different zone", authorizationTime.In(time.FixedZone("offset", 2*60*60)), true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorization, err := authz.NewContext(input).AuthorizeEnquiryCreation(test.at)
			if test.valid {
				if err != nil || !authorization.Valid() || !authorization.AuthorizedAt().Equal(test.at) {
					t.Fatalf("valid instant denied or changed: %v", err)
				}
				if authorization.AuthorizedAt().Location() != time.UTC {
					t.Fatal("audit instant must be normalized to UTC")
				}
			} else if !errors.Is(err, authz.ErrUnauthorized) || authorization.Valid() {
				t.Fatalf("invalid instant authorized: %v", err)
			}
		})
	}
}

func TestContextSnapshotsCallerInput(t *testing.T) {
	input := validContextInput()
	context := authz.NewContext(input)
	input.Actor.ID = "replacement-actor"
	input.ActiveOrganizationID = "replacement-org"
	input.Membership.Active = false
	input.Membership.Capabilities[0] = "enquiries.read"
	authorization, err := context.AuthorizeEnquiryCreation(authorizationTime)
	if err != nil || !authorization.Valid() {
		t.Fatalf("caller mutation changed valid context: %v", err)
	}
	if authorization.ActorID() != "actor-1" || authorization.OrganizationID() != "org-1" {
		t.Fatal("caller mutation changed attributable facts")
	}

	deniedInput := validContextInput()
	deniedInput.Membership.Capabilities[0] = "enquiries.read"
	deniedContext := authz.NewContext(deniedInput)
	deniedInput.Membership.Capabilities[0] = authz.CapabilityCreateEnquiry
	if _, err := deniedContext.AuthorizeEnquiryCreation(authorizationTime); !errors.Is(err, authz.ErrUnauthorized) {
		t.Fatal("caller mutation escalated a context without create capability")
	}
}

func TestAuthorizationZerosDeny(t *testing.T) {
	var context authz.Context
	authorization, err := context.AuthorizeEnquiryCreation(authorizationTime)
	if !errors.Is(err, authz.ErrUnauthorized) || authorization.Valid() {
		t.Fatal("zero context must deny")
	}
	var zero authz.CreationAuthorization
	if zero.Valid() || zero.ActorID() != "" || zero.OrganizationID() != "" ||
		zero.MembershipID() != "" || !zero.AuthorizedAt().IsZero() {
		t.Fatal("zero authorization must be invalid and contain no facts")
	}
}

func TestAuthorizationDoesNotChangeContextAfterDenial(t *testing.T) {
	context := authz.NewContext(validContextInput())
	if _, err := context.AuthorizeEnquiryCreation(authorizationTime.Add(2 * time.Hour)); !errors.Is(err, authz.ErrUnauthorized) {
		t.Fatal("expired check must deny")
	}
	authorization, err := context.AuthorizeEnquiryCreation(authorizationTime)
	if err != nil || !authorization.Valid() {
		t.Fatalf("denied check mutated the context: %v", err)
	}
}
