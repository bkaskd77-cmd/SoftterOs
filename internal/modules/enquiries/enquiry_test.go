package enquiries_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
)

func creationTime() time.Time {
	return time.Date(2026, time.October, 26, 10, 30, 0, 0, time.UTC)
}

func validInput() enquiries.Input {
	return enquiries.Input{
		ContactName:    "Alex Example",
		ContactEmail:   "alex@example.com",
		Destination:    "Oslo, Norway",
		TravellerCount: 2,
		TravelStart:    "2026-11-02",
		TravelEnd:      "2026-11-06",
	}
}

func authorization(t *testing.T, organizationID string, at time.Time) authz.CreationAuthorization {
	t.Helper()
	context := authz.NewContext(authz.ContextInput{
		Actor:                authz.Actor{ID: "actor-1", Authenticated: true},
		ActiveOrganizationID: organizationID,
		Membership: authz.Membership{
			ID:             "membership-1",
			ActorID:        "actor-1",
			OrganizationID: organizationID,
			Active:         true,
			ValidFrom:      at.Add(-time.Hour),
			ValidUntil:     at.Add(time.Hour),
			Capabilities:   []authz.Capability{authz.CapabilityCreateEnquiry},
		},
	})
	grant, err := context.AuthorizeEnquiryCreation(at)
	if err != nil {
		t.Fatalf("authorize test creation: %v", err)
	}
	return grant
}

func assertNoEnquiry(t *testing.T, enquiry enquiries.Enquiry) {
	t.Helper()
	if enquiry.ID() != "" || enquiry.OrganizationID() != "" || enquiry.CreatedBy() != "" || enquiry.MembershipID() != "" || enquiry.State() != "" || !enquiry.CreatedAt().IsZero() {
		t.Fatal("failed creation returned an enquiry or attribution")
	}
	if enquiry.Input() != (enquiries.Input{}) || enquiry.CreationAudit() != (enquiries.CreationAudit{}) {
		t.Fatal("failed creation returned input or an audit event")
	}
}

func TestNewAuthorizedEnquiry(t *testing.T) {
	at := creationTime()
	input := validInput()
	grant := authorization(t, "organization-1", at)
	enquiry, err := enquiries.New("enquiry-1", input, grant)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if enquiry.ID() != "enquiry-1" || enquiry.OrganizationID() != "organization-1" {
		t.Fatal("incorrect enquiry identity or ownership")
	}
	if enquiry.State() != enquiries.StateNew || string(enquiry.State()) != "New" {
		t.Fatalf("initial state = %q; want canonical New", enquiry.State())
	}
	if enquiry.CreatedBy() != "actor-1" || enquiry.MembershipID() != "membership-1" || !enquiry.CreatedAt().Equal(at) {
		t.Fatal("missing or incorrect creator attribution")
	}
	if enquiry.CreatedAt().Location() != time.UTC {
		t.Fatal("creation timestamp must be UTC")
	}
	if enquiry.Input() != input {
		t.Fatal("captured input was unexpectedly changed")
	}
	wantAudit := enquiries.CreationAudit{
		Action:         "enquiry.created",
		EnquiryID:      "enquiry-1",
		OrganizationID: "organization-1",
		ActorID:        "actor-1",
		MembershipID:   "membership-1",
		At:             at,
		Capability:     authz.CapabilityCreateEnquiry,
	}
	if enquiry.CreationAudit() != wantAudit {
		t.Fatal("creation audit does not contain the authorized creation facts")
	}
}

func TestOwnershipComesOnlyFromAuthorization(t *testing.T) {
	input := validInput()
	input.ContactName = "organization-caller"
	input.Destination = "organization-caller"
	for _, organizationID := range []string{"organization-a", "organization-b"} {
		t.Run(organizationID, func(t *testing.T) {
			grant := authorization(t, organizationID, creationTime())
			enquiry, err := enquiries.New("enquiry-1", input, grant)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if enquiry.OrganizationID() != organizationID || enquiry.CreationAudit().OrganizationID != organizationID {
				t.Fatal("ownership did not come from authorization")
			}
		})
	}
}

func TestEnquiryCannotBeChangedThroughInputOrAuditCopies(t *testing.T) {
	input := validInput()
	original := input
	enquiry, err := enquiries.New("enquiry-1", input, authorization(t, "organization-1", creationTime()))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	input.ContactName = "Changed caller input"
	copyOfInput := enquiry.Input()
	copyOfInput.ContactEmail = "changed@example.com"
	copyOfInput.TravellerCount = 99
	copyOfAudit := enquiry.CreationAudit()
	copyOfAudit.OrganizationID = "organization-other"
	copyOfAudit.ActorID = "actor-other"
	copyOfAudit.Action = "unapproved.action"
	if enquiry.Input() != original || enquiry.OrganizationID() != "organization-1" || enquiry.CreatedBy() != "actor-1" || enquiry.State() != enquiries.StateNew {
		t.Fatal("changing a detached value mutated the enquiry")
	}
	if enquiry.CreationAudit().Action != "enquiry.created" || enquiry.CreationAudit().OrganizationID != "organization-1" || enquiry.CreationAudit().ActorID != "actor-1" {
		t.Fatal("changing a detached audit value mutated creation facts")
	}
}

func TestNewRejectsZeroAuthorizationBeforeInputValidation(t *testing.T) {
	for _, input := range []enquiries.Input{validInput(), {}} {
		enquiry, err := enquiries.New("", input, authz.CreationAuthorization{})
		if !errors.Is(err, authz.ErrUnauthorized) {
			t.Fatalf("error = %v; want unauthorized", err)
		}
		assertNoEnquiry(t, enquiry)
	}
}

func TestNewRejectsInvalidIdentifiers(t *testing.T) {
	grant := authorization(t, "organization-1", creationTime())
	for _, id := range []string{"", " ", " enquiry-1", "enquiry-1 ", "-enquiry", "_enquiry", "enquiry/1", "enquiry.1", "enquiry\n1", "enquiry-ø", strings.Repeat("a", 129)} {
		t.Run(id, func(t *testing.T) {
			enquiry, err := enquiries.New(id, validInput(), grant)
			if err != enquiries.ErrInvalidID {
				t.Fatalf("error = %v; want safe invalid identifier sentinel", err)
			}
			assertNoEnquiry(t, enquiry)
		})
	}
	for _, id := range []string{"a", "Enquiry_1-X", strings.Repeat("a", 128)} {
		if _, err := enquiries.New(id, validInput(), grant); err != nil {
			t.Fatalf("valid identifier rejected: %v", err)
		}
	}
}

func TestNewRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name   string
		change func(*enquiries.Input)
	}{
		{"missing contact name", func(i *enquiries.Input) { i.ContactName = "" }},
		{"blank contact name", func(i *enquiries.Input) { i.ContactName = "   " }},
		{"untrimmed contact name", func(i *enquiries.Input) { i.ContactName = " Alex" }},
		{"long contact name", func(i *enquiries.Input) { i.ContactName = strings.Repeat("ø", 121) }},
		{"control in contact name", func(i *enquiries.Input) { i.ContactName = "Alex\nExample" }},
		{"line separator in contact name", func(i *enquiries.Input) { i.ContactName = "Alex\u2028Example" }},
		{"invalid utf8 contact name", func(i *enquiries.Input) { i.ContactName = string([]byte{0xff}) }},
		{"missing email", func(i *enquiries.Input) { i.ContactEmail = "" }},
		{"malformed email", func(i *enquiries.Input) { i.ContactEmail = "not-an-address" }},
		{"email without local part", func(i *enquiries.Input) { i.ContactEmail = "@example.com" }},
		{"email without domain", func(i *enquiries.Input) { i.ContactEmail = "alex@" }},
		{"display name email", func(i *enquiries.Input) { i.ContactEmail = "Alex <alex@example.com>" }},
		{"multiple emails", func(i *enquiries.Input) { i.ContactEmail = "alex@example.com,sam@example.com" }},
		{"untrimmed email", func(i *enquiries.Input) { i.ContactEmail = "alex@example.com " }},
		{"email header injection", func(i *enquiries.Input) { i.ContactEmail = "alex@example.com\r\nBcc:other@example.com" }},
		{"long email", func(i *enquiries.Input) { i.ContactEmail = strings.Repeat("a", 255) + "@example.com" }},
		{"missing destination", func(i *enquiries.Input) { i.Destination = "" }},
		{"untrimmed destination", func(i *enquiries.Input) { i.Destination = "Oslo " }},
		{"long destination", func(i *enquiries.Input) { i.Destination = strings.Repeat("a", 201) }},
		{"control in destination", func(i *enquiries.Input) { i.Destination = "Oslo\x00Norway" }},
		{"invalid utf8 destination", func(i *enquiries.Input) { i.Destination = string([]byte{0xff}) }},
		{"no travellers", func(i *enquiries.Input) { i.TravellerCount = 0 }},
		{"negative travellers", func(i *enquiries.Input) { i.TravellerCount = -1 }},
		{"too many travellers", func(i *enquiries.Input) { i.TravellerCount = 100 }},
	}
	grant := authorization(t, "organization-1", creationTime())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := validInput()
			tc.change(&input)
			if err := enquiries.ValidateInput(input, creationTime()); err != enquiries.ErrInvalidInput {
				t.Fatalf("validation error = %v; want safe invalid input sentinel", err)
			}
			enquiry, err := enquiries.New("enquiry-1", input, grant)
			if err != enquiries.ErrInvalidInput {
				t.Fatalf("creation error = %v; want safe invalid input sentinel", err)
			}
			assertNoEnquiry(t, enquiry)
		})
	}
}

func TestValidInputBoundaries(t *testing.T) {
	input := validInput()
	input.ContactName = strings.Repeat("ø", 120)
	input.Destination = strings.Repeat("山", 200)
	for _, count := range []int{1, 99} {
		input.TravellerCount = count
		if _, err := enquiries.New("enquiry-1", input, authorization(t, "organization-1", creationTime())); err != nil {
			t.Fatalf("valid boundary input rejected: %v", err)
		}
	}
}

func TestTravelDates(t *testing.T) {
	cases := []struct {
		name  string
		start string
		end   string
		valid bool
	}{
		{"unknown dates", "", "", true},
		{"same day", "2026-10-26", "2026-10-26", true},
		{"ordered range", "2026-11-02", "2026-11-06", true},
		{"valid leap day", "2028-02-29", "2028-03-01", true},
		{"missing start", "", "2026-11-06", false},
		{"missing end", "2026-11-02", "", false},
		{"reversed range", "2026-11-06", "2026-11-02", false},
		{"past start", "2026-10-25", "2026-11-02", false},
		{"past range", "2026-10-23", "2026-10-25", false},
		{"invalid leap day", "2027-02-29", "2027-03-01", false},
		{"invalid month", "2026-13-01", "2027-01-02", false},
		{"invalid day", "2026-11-31", "2026-12-02", false},
		{"day zero", "2026-11-00", "2026-11-02", false},
		{"nonpadded month", "2026-1-26", "2026-11-02", false},
		{"nonpadded day", "2026-11-2", "2026-11-06", false},
		{"datetime supplied", "2026-11-02T00:00:00Z", "2026-11-06", false},
		{"locale date", "02/11/2026", "06/11/2026", false},
		{"leading whitespace", " 2026-11-02", "2026-11-06", false},
		{"trailing whitespace", "2026-11-02", "2026-11-06 ", false},
		{"year zero", "0000-11-02", "2026-11-06", false},
		{"invalid end", "2026-11-02", "2026-11-31", false},
	}
	grant := authorization(t, "organization-1", creationTime())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := validInput()
			input.TravelStart, input.TravelEnd = tc.start, tc.end
			enquiry, err := enquiries.New("enquiry-1", input, grant)
			if tc.valid {
				if err != nil {
					t.Fatalf("valid dates rejected: %v", err)
				}
				if enquiry.Input().TravelStart != tc.start || enquiry.Input().TravelEnd != tc.end {
					t.Fatal("valid dates unexpectedly rewritten")
				}
			} else {
				if err != enquiries.ErrInvalidInput {
					t.Fatalf("error = %v; want safe invalid input sentinel", err)
				}
				assertNoEnquiry(t, enquiry)
			}
		})
	}
}

func TestTravelDateUsesUTCCreationDay(t *testing.T) {
	at := time.Date(2026, time.October, 26, 0, 30, 0, 0, time.FixedZone("UTC+02", 2*60*60))
	input := validInput()
	input.TravelStart, input.TravelEnd = "2026-10-25", "2026-10-25"
	enquiry, err := enquiries.New("enquiry-1", input, authorization(t, "organization-1", at))
	if err != nil {
		t.Fatalf("UTC creation day incorrectly treated as past: %v", err)
	}
	if !enquiry.CreatedAt().Equal(at) || enquiry.CreatedAt().Location() != time.UTC {
		t.Fatal("creation timestamp did not preserve its instant in UTC")
	}
}

func TestValidateInputRejectsInvalidCreationTime(t *testing.T) {
	input := validInput()
	input.TravelStart, input.TravelEnd = "", ""
	for _, at := range []time.Time{time.Time{}, time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if err := enquiries.ValidateInput(input, at); err != enquiries.ErrInvalidInput {
			t.Fatalf("error = %v; want invalid input for invalid creation time", err)
		}
	}
}
