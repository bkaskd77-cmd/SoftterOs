package application_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries/application"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
)

var creationTime = time.Date(2026, time.October, 26, 10, 30, 0, 0, time.UTC)

func validContextInput() authz.ContextInput {
	return authz.ContextInput{
		Actor:                authz.Actor{ID: "actor-1", Authenticated: true},
		ActiveOrganizationID: "org-1",
		Membership: authz.Membership{
			ID: "membership-1", ActorID: "actor-1", OrganizationID: "org-1",
			Active: true, ValidFrom: creationTime.Add(-time.Hour), ValidUntil: creationTime.Add(time.Hour),
			Capabilities: []authz.Capability{authz.CapabilityCreateEnquiry},
		},
	}
}

func validInput() enquiries.Input {
	return enquiries.Input{
		ContactName: "Example Contact", ContactEmail: "contact@example.com",
		Destination: "Norway", TravellerCount: 2,
		TravelStart: "2027-02-01", TravelEnd: "2027-02-10",
	}
}

func TestAuthorizedCreationReturnsOwnedNewEnquiryAndAudit(t *testing.T) {
	clockCalls, idCalls := 0, 0
	creator, err := application.NewCreator(func() time.Time {
		clockCalls++
		return creationTime
	}, func() (string, error) {
		idCalls++
		return "enquiry-1", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := creator.Create(authz.NewContext(validContextInput()), validInput())
	if err != nil {
		t.Fatal(err)
	}
	if clockCalls != 1 || idCalls != 1 {
		t.Fatalf("dependency calls: clock=%d id=%d; want one each", clockCalls, idCalls)
	}
	e := result.Enquiry
	if e.ID() != "enquiry-1" || e.OrganizationID() != "org-1" || e.State() != enquiries.StateNew || string(e.State()) != "New" {
		t.Fatal("incorrect ID, organization ownership, or canonical initial state")
	}
	if e.CreatedBy() != "actor-1" || e.MembershipID() != "membership-1" || !e.CreatedAt().Equal(creationTime) {
		t.Fatal("missing creator, membership, or creation-time attribution")
	}
	audit := result.Audit
	if audit.Action != "enquiry.created" || audit.EnquiryID != e.ID() || audit.OrganizationID != e.OrganizationID() ||
		audit.ActorID != e.CreatedBy() || audit.MembershipID != e.MembershipID() || !audit.At.Equal(e.CreatedAt()) ||
		audit.Capability != authz.CapabilityCreateEnquiry {
		t.Fatal("audit facts do not match the authorized creation")
	}
	result.Audit.OrganizationID = "other-org"
	inputCopy := e.Input()
	inputCopy.Destination = "Changed"
	if e.CreationAudit().OrganizationID != "org-1" || e.Input().Destination != "Norway" {
		t.Fatal("caller mutated authoritative enquiry facts through returned values")
	}
}

func TestAuthorizationDenialDoesNotGenerateIdentifierOrReturnResource(t *testing.T) {
	cases := []struct {
		name   string
		change func(*authz.ContextInput)
	}{
		{"missing actor", func(c *authz.ContextInput) { c.Actor = authz.Actor{} }},
		{"unauthenticated", func(c *authz.ContextInput) { c.Actor.Authenticated = false }},
		{"missing active organization", func(c *authz.ContextInput) { c.ActiveOrganizationID = "" }},
		{"malformed active organization", func(c *authz.ContextInput) { c.ActiveOrganizationID = "org-1\n" }},
		{"missing membership", func(c *authz.ContextInput) { c.Membership = authz.Membership{} }},
		{"inactive membership", func(c *authz.ContextInput) { c.Membership.Active = false }},
		{"invalid membership identity", func(c *authz.ContextInput) { c.Membership.ID = " " }},
		{"expired membership", func(c *authz.ContextInput) { c.Membership.ValidUntil = creationTime }},
		{"future membership", func(c *authz.ContextInput) { c.Membership.ValidFrom = creationTime.Add(time.Minute) }},
		{"invalid validity range", func(c *authz.ContextInput) { c.Membership.ValidUntil = c.Membership.ValidFrom }},
		{"missing capability", func(c *authz.ContextInput) { c.Membership.Capabilities = nil }},
		{"wrong capability", func(c *authz.ContextInput) { c.Membership.Capabilities = []authz.Capability{"enquiries.read"} }},
		{"cross organization", func(c *authz.ContextInput) { c.ActiveOrganizationID = "org-2" }},
		{"cross actor", func(c *authz.ContextInput) { c.Membership.ActorID = "actor-2" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := validContextInput()
			tc.change(&facts)
			calls := 0
			creator, err := application.NewCreator(func() time.Time { return creationTime }, func() (string, error) {
				calls++
				return "unexpected", nil
			})
			if err != nil {
				t.Fatal(err)
			}
			// Invalid input also confirms that authorization is checked first.
			result, err := creator.Create(authz.NewContext(facts), enquiries.Input{})
			if !errors.Is(err, authz.ErrUnauthorized) || calls != 0 {
				t.Fatalf("got err=%v, identifier calls=%d; want denial with no identifier call", err, calls)
			}
			assertEmptyResult(t, result)
		})
	}
}

func TestOwnershipComesFromEachValidatedContext(t *testing.T) {
	creator, err := application.NewCreator(func() time.Time { return creationTime }, func() (string, error) { return "enquiry-1", nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, organization := range []string{"org-1", "org-2"} {
		facts := validContextInput()
		facts.ActiveOrganizationID = organization
		facts.Membership.OrganizationID = organization
		result, err := creator.Create(authz.NewContext(facts), validInput())
		if err != nil || result.Enquiry.OrganizationID() != organization || result.Audit.OrganizationID != organization {
			t.Fatalf("ownership was not derived from current context: %v", err)
		}
	}
}

func TestInvalidInputDoesNotGenerateIdentifier(t *testing.T) {
	input := validInput()
	input.TravelEnd = "2027-01-31"
	calls := 0
	creator, err := application.NewCreator(func() time.Time { return creationTime }, func() (string, error) {
		calls++
		return "unexpected", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := creator.Create(authz.NewContext(validContextInput()), input)
	if !errors.Is(err, enquiries.ErrInvalidInput) || calls != 0 {
		t.Fatalf("got err=%v, identifier calls=%d", err, calls)
	}
	assertEmptyResult(t, result)
}

func TestSafeDependencyFailures(t *testing.T) {
	cases := []struct {
		name string
		now  func() time.Time
		id   func() (string, error)
		want error
	}{
		{"zero time", func() time.Time { return time.Time{} }, func() (string, error) { t.Fatal("ID called after invalid clock"); return "", nil }, authz.ErrUnauthorized},
		{"identifier failure", func() time.Time { return creationTime }, func() (string, error) { return "discard-me", errors.New("internal provider detail") }, application.ErrIdentifierGeneration},
		{"malformed identifier", func() time.Time { return creationTime }, func() (string, error) { return "bad id", nil }, enquiries.ErrInvalidID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			creator, err := application.NewCreator(tc.now, tc.id)
			if err != nil {
				t.Fatal(err)
			}
			result, err := creator.Create(authz.NewContext(validContextInput()), validInput())
			if err != tc.want {
				t.Fatalf("got %v; want safe error %v", err, tc.want)
			}
			assertEmptyResult(t, result)
		})
	}
}

func TestMissingDependenciesFailSafely(t *testing.T) {
	if _, err := application.NewCreator(nil, func() (string, error) { return "id-1", nil }); err != application.ErrConfiguration {
		t.Fatalf("nil clock: %v", err)
	}
	if _, err := application.NewCreator(func() time.Time { return creationTime }, nil); err != application.ErrConfiguration {
		t.Fatalf("nil generator: %v", err)
	}
	var creator application.Creator
	result, err := creator.Create(authz.NewContext(validContextInput()), validInput())
	if err != application.ErrConfiguration {
		t.Fatalf("uninitialized creator: %v", err)
	}
	assertEmptyResult(t, result)
}

func assertEmptyResult(t *testing.T, result application.Result) {
	t.Helper()
	if !reflect.DeepEqual(result, application.Result{}) {
		t.Fatal("failure returned a partial enquiry or success audit")
	}
}
