package enquiries_test

import (
	"strings"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
)

var snapshotTime = time.Date(2026, 10, 28, 12, 0, 0, 123456789, time.UTC)

func storedSnapshot() enquiries.Snapshot {
	return enquiries.Snapshot{
		ID: "enquiry-7", OrganizationID: "org-7", State: enquiries.StateNew,
		CreatedBy: "creator-7", MembershipID: "creator-membership-7",
		CreatedAt: snapshotTime, LastChangedAt: snapshotTime, Version: 1,
		Input: enquiries.Input{
			ContactName: "Synthetic Contact", ContactEmail: "contact@example.com",
			Destination: "Norway", TravellerCount: 3,
			TravelStart: "2020-02-29", TravelEnd: "2020-03-02",
		},
	}
}

func snapshotProof(t *testing.T, e enquiries.Enquiry, capability authz.Capability, actor, membership string, at time.Time) authz.EnquiryTransitionAuthorization {
	t.Helper()
	context := authz.NewContext(authz.ContextInput{
		Actor: authz.Actor{ID: actor, Authenticated: true, Human: true}, ActiveOrganizationID: e.OrganizationID(),
		Membership: authz.Membership{
			ID: membership, ActorID: actor, OrganizationID: e.OrganizationID(), Active: true,
			ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour), Capabilities: []authz.Capability{capability},
		},
		TransitionGrant: authz.EnquiryTransitionGrant{
			ID: "grant-" + actor, ActorID: actor, MembershipID: membership,
			OrganizationID: e.OrganizationID(), EnquiryID: e.ID(), Capability: capability, Active: true,
			ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour),
		},
	})
	proof, err := context.AuthorizeEnquiryTransition(e.ID(), e.OrganizationID(), capability, at)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestSnapshotRoundTripsReachableStates(t *testing.T) {
	for _, suffix := range []string{"7", "23"} {
		t.Run(suffix, func(t *testing.T) {
			want := storedSnapshot()
			want.ID, want.OrganizationID = "enquiry-"+suffix, "org-"+suffix
			want.CreatedBy, want.MembershipID = "creator-"+suffix, "creator-membership-"+suffix
			reviewer, assignee := "reviewer-"+suffix, "review-membership-"+suffix
			initial, err := enquiries.New(want.ID, want.Input, authorizationFor(t, want.CreatedBy, want.MembershipID, want.OrganizationID, want.CreatedAt))
			if err != nil {
				t.Fatal(err)
			}
			reviewAt, qualifyAt := snapshotTime.Add(time.Minute+17*time.Nanosecond), snapshotTime.Add(2*time.Minute+31*time.Nanosecond)
			review, err := initial.StartReview(snapshotProof(t, initial, authz.CapabilityReviewEnquiry, reviewer, assignee, reviewAt), 1, reviewAt)
			if err != nil {
				t.Fatal(err)
			}
			qualified, err := review.Enquiry.Qualify(snapshotProof(t, review.Enquiry, authz.CapabilityQualifyEnquiry, reviewer, assignee, qualifyAt), 2, qualifyAt)
			if err != nil {
				t.Fatal(err)
			}
			priorReviewAudit, priorQualificationAudit := review.Audit, qualified.Audit
			creationAudit := enquiries.CreationAudit{
				Action: "enquiry.created", EnquiryID: want.ID, OrganizationID: want.OrganizationID,
				ActorID: want.CreatedBy, MembershipID: want.MembershipID, At: want.CreatedAt,
				Capability: authz.CapabilityCreateEnquiry,
			}
			for _, tc := range []struct {
				enquiry enquiries.Enquiry
				state   enquiries.State
				version uint64
				changed time.Time
			}{
				{initial, enquiries.StateNew, 1, snapshotTime},
				{review.Enquiry, enquiries.StateUnderReview, 2, reviewAt},
				{qualified.Enquiry, enquiries.StateQualified, 3, qualifyAt},
			} {
				t.Run(string(tc.state), func(t *testing.T) {
					expected := want
					expected.State, expected.Version, expected.LastChangedAt = tc.state, tc.version, tc.changed
					if tc.state != enquiries.StateNew {
						expected.AssigneeMembershipID = assignee
					}
					snapshot := tc.enquiry.Snapshot()
					// Independent expected values catch paired export/restore omissions.
					if snapshot != expected {
						t.Fatal("export lost domain state, historical input, attribution, or timestamp precision")
					}
					restored, err := enquiries.Restore(snapshot)
					if err != nil || restored != tc.enquiry || restored.Snapshot() != expected || restored.CreationAudit() != creationAudit {
						t.Fatalf("round trip did not preserve the complete enquiry and historical creation audit: %v", err)
					}
					if review.Audit != priorReviewAudit || qualified.Audit != priorQualificationAudit {
						t.Fatal("restoration changed detached transition audit facts")
					}
					snapshot.Input.ContactEmail = "changed@example.com"
					snapshot.CreatedBy, snapshot.MembershipID, snapshot.OrganizationID = "changed", "changed", "changed"
					snapshot.AssigneeMembershipID, snapshot.State = "changed", enquiries.StateNew
					snapshot.Version, snapshot.LastChangedAt = 99, time.Time{}
					anotherCopy := restored.Snapshot()
					anotherCopy.Input.Destination = "Changed"
					if restored != tc.enquiry || restored.Snapshot() != expected || tc.enquiry.Snapshot() != expected || restored.CreationAudit() != creationAudit {
						t.Fatal("mutating snapshot copies changed the original or restored enquiry")
					}
				})
			}
		})
	}
}

func assertSnapshotRejected(t *testing.T, snapshot enquiries.Snapshot) {
	t.Helper()
	before := snapshot
	restored, err := enquiries.Restore(snapshot)
	if err != enquiries.ErrInvalidSnapshot || err.Error() != "invalid enquiry snapshot" {
		t.Fatalf("restore error = %v; want stable safe snapshot error", err)
	}
	if restored != (enquiries.Enquiry{}) || restored.CreationAudit() != (enquiries.CreationAudit{}) || restored.Snapshot() != (enquiries.Snapshot{}) {
		t.Fatal("invalid snapshot returned partial state or historical audit facts")
	}
	if snapshot != before {
		t.Fatal("rejection changed the supplied snapshot")
	}
}

func TestRestoreRejectsInvalidSnapshotIdentifiers(t *testing.T) {
	for _, field := range []struct {
		name string
		set  func(*enquiries.Snapshot, string)
	}{
		{"enquiry", func(s *enquiries.Snapshot, id string) { s.ID = id }},
		{"organization", func(s *enquiries.Snapshot, id string) { s.OrganizationID = id }},
		{"creator", func(s *enquiries.Snapshot, id string) { s.CreatedBy = id }},
		{"creator membership", func(s *enquiries.Snapshot, id string) { s.MembershipID = id }},
		{"assignee membership", func(s *enquiries.Snapshot, id string) { s.AssigneeMembershipID = id }},
	} {
		t.Run(field.name, func(t *testing.T) {
			for _, id := range []string{"", "-id", "_id", "id with space", "id/part", "id.part", "id\n", "id-ø", strings.Repeat("x", 129)} {
				snapshot := storedSnapshot()
				snapshot.State, snapshot.Version, snapshot.AssigneeMembershipID = enquiries.StateUnderReview, 2, "review-membership"
				field.set(&snapshot, id)
				assertSnapshotRejected(t, snapshot)
			}
		})
	}
}

func TestRestoreRejectsInvalidSnapshotInput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*enquiries.Input)
	}{
		{"missing name", func(i *enquiries.Input) { i.ContactName = "" }},
		{"untrimmed name", func(i *enquiries.Input) { i.ContactName = " Synthetic" }},
		{"long name", func(i *enquiries.Input) { i.ContactName = strings.Repeat("ø", 121) }},
		{"control in name", func(i *enquiries.Input) { i.ContactName = "Synthetic\nContact" }},
		{"invalid UTF8", func(i *enquiries.Input) { i.Destination = string([]byte{0xff}) }},
		{"missing destination", func(i *enquiries.Input) { i.Destination = "" }},
		{"long destination", func(i *enquiries.Input) { i.Destination = strings.Repeat("x", 201) }},
		{"invalid email", func(i *enquiries.Input) { i.ContactEmail = "invalid" }},
		{"display name email", func(i *enquiries.Input) { i.ContactEmail = "Name <contact@example.com>" }},
		{"no travellers", func(i *enquiries.Input) { i.TravellerCount = 0 }},
		{"too many travellers", func(i *enquiries.Input) { i.TravellerCount = 100 }},
		{"incomplete start", func(i *enquiries.Input) { i.TravelStart = "" }},
		{"incomplete end", func(i *enquiries.Input) { i.TravelEnd = "" }},
		{"malformed date", func(i *enquiries.Input) { i.TravelStart = "2020-2-29" }},
		{"invalid calendar date", func(i *enquiries.Input) { i.TravelStart = "2019-02-29" }},
		{"reversed historical dates", func(i *enquiries.Input) { i.TravelStart = "2020-03-03" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := storedSnapshot()
			tc.change(&snapshot.Input)
			assertSnapshotRejected(t, snapshot)
		})
	}
}

func TestRestoreRejectsInconsistentSnapshotState(t *testing.T) {
	for _, tc := range []struct {
		name     string
		state    enquiries.State
		version  uint64
		assignee string
	}{
		{"empty state", "", 1, ""},
		{"unknown state", "unknown", 1, ""},
		{"unimplemented state", "Drafting", 3, "review-membership"},
		{"state case", "new", 1, ""},
		{"new assigned", enquiries.StateNew, 1, "review-membership"},
		{"new zero version", enquiries.StateNew, 0, ""},
		{"new advanced version", enquiries.StateNew, 2, ""},
		{"review unassigned", enquiries.StateUnderReview, 2, ""},
		{"review zero version", enquiries.StateUnderReview, 0, "review-membership"},
		{"review creation version", enquiries.StateUnderReview, 1, "review-membership"},
		{"review advanced version", enquiries.StateUnderReview, 3, "review-membership"},
		{"qualified unassigned", enquiries.StateQualified, 3, ""},
		{"qualified malformed assignee", enquiries.StateQualified, 3, "invalid membership"},
		{"qualified zero version", enquiries.StateQualified, 0, "review-membership"},
		{"qualified creation version", enquiries.StateQualified, 1, "review-membership"},
		{"qualified review version", enquiries.StateQualified, 2, "review-membership"},
		{"qualified advanced version", enquiries.StateQualified, 4, "review-membership"},
		{"version overflow boundary", enquiries.StateQualified, ^uint64(0), "review-membership"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := storedSnapshot()
			snapshot.State, snapshot.Version, snapshot.AssigneeMembershipID = tc.state, tc.version, tc.assignee
			assertSnapshotRejected(t, snapshot)
		})
	}
	assertSnapshotRejected(t, enquiries.Snapshot{})
	var zero enquiries.Enquiry
	if zero.Snapshot() != (enquiries.Snapshot{}) {
		t.Fatal("zero enquiry exported fabricated state")
	}
}

func TestRestoreSnapshotTimeValidationAndPrecision(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*enquiries.Snapshot)
	}{
		{"zero creation", func(s *enquiries.Snapshot) { s.CreatedAt = time.Time{} }},
		{"creation below range", func(s *enquiries.Snapshot) { s.CreatedAt = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"creation above range", func(s *enquiries.Snapshot) {
			s.CreatedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			s.LastChangedAt = s.CreatedAt
		}},
		{"zero last change", func(s *enquiries.Snapshot) { s.LastChangedAt = time.Time{} }},
		{"last change below range", func(s *enquiries.Snapshot) { s.LastChangedAt = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"last change above range", func(s *enquiries.Snapshot) { s.LastChangedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"before creation by one nanosecond", func(s *enquiries.Snapshot) { s.LastChangedAt = s.CreatedAt.Add(-time.Nanosecond) }},
		{"local year valid but UTC year invalid", func(s *enquiries.Snapshot) {
			s.CreatedAt = time.Date(1, 1, 1, 0, 0, 0, 1, time.FixedZone("east", 3600))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := storedSnapshot()
			snapshot.State, snapshot.Version, snapshot.AssigneeMembershipID = enquiries.StateUnderReview, 2, "review-membership"
			tc.change(&snapshot)
			assertSnapshotRejected(t, snapshot)
		})
	}
	newChanged := storedSnapshot()
	newChanged.LastChangedAt = newChanged.CreatedAt.Add(time.Nanosecond)
	assertSnapshotRejected(t, newChanged)

	for _, at := range []time.Time{
		time.Date(1, 1, 1, 0, 0, 0, 1, time.UTC),
		snapshotTime,
		time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC),
	} {
		for _, state := range []enquiries.State{enquiries.StateNew, enquiries.StateUnderReview, enquiries.StateQualified} {
			snapshot := storedSnapshot()
			snapshot.CreatedAt, snapshot.LastChangedAt = at, at
			snapshot.State = state
			if state == enquiries.StateUnderReview {
				snapshot.Version, snapshot.AssigneeMembershipID = 2, "review-membership"
			} else if state == enquiries.StateQualified {
				snapshot.Version, snapshot.AssigneeMembershipID = 3, "review-membership"
			}
			// Equal action instants are valid; precision must not collapse into zero
			// or round into year 10000 at the accepted boundaries.
			restored, err := enquiries.Restore(snapshot)
			if err != nil || restored.Snapshot() != snapshot {
				t.Fatalf("valid timestamp boundary or equal-instant state changed: %v", err)
			}
		}
	}
	stored := storedSnapshot()
	stored.CreatedAt = stored.CreatedAt.In(time.FixedZone("east", 3600))
	stored.LastChangedAt = stored.LastChangedAt.In(time.FixedZone("west", -3600))
	restored, err := enquiries.Restore(stored)
	if err != nil || restored.Snapshot() != storedSnapshot() {
		t.Fatalf("equivalent zones failed to retain the exact UTC instant: %v", err)
	}
	unknownDates := storedSnapshot()
	unknownDates.Input.TravelStart, unknownDates.Input.TravelEnd = "", ""
	restored, err = enquiries.Restore(unknownDates)
	if err != nil || restored.Snapshot() != unknownDates {
		t.Fatalf("unknown travel dates rejected or changed: %v", err)
	}
}

func TestRestoredEnquiryStillRequiresCurrentAuthority(t *testing.T) {
	stored := storedSnapshot()
	creatorFacts := authz.ContextInput{
		Actor: authz.Actor{ID: stored.CreatedBy, Authenticated: true}, ActiveOrganizationID: stored.OrganizationID,
		Membership: authz.Membership{
			ID: stored.MembershipID, ActorID: stored.CreatedBy, OrganizationID: stored.OrganizationID,
			Active: true, ValidFrom: snapshotTime.Add(-time.Hour), ValidUntil: snapshotTime.Add(time.Hour),
			Capabilities: []authz.Capability{authz.CapabilityCreateEnquiry},
		},
	}
	authorization, err := authz.NewContext(creatorFacts).AuthorizeEnquiryCreation(snapshotTime)
	if err != nil {
		t.Fatal(err)
	}
	original, err := enquiries.New(stored.ID, stored.Input, authorization)
	if err != nil {
		t.Fatal(err)
	}
	creatorFacts.Membership.Revoked = true
	if _, err := authz.NewContext(creatorFacts).AuthorizeEnquiryCreation(snapshotTime); err != authz.ErrUnauthorized {
		t.Fatal("revoked creator fixture must deny new creation")
	}
	restored, err := enquiries.Restore(original.Snapshot())
	if err != nil || restored != original || restored.CreationAudit() != original.CreationAudit() {
		t.Fatalf("historical attribution could not be reconstructed after creator revocation: %v", err)
	}
	at := snapshotTime.Add(time.Minute + 1*time.Nanosecond)
	result, err := restored.StartReview(authz.EnquiryTransitionAuthorization{}, 1, at)
	if err != authz.ErrTransitionUnauthorized || result != (enquiries.TransitionResult{}) || restored != original {
		t.Fatal("restoration conferred review authority or changed historical state")
	}
	proof := snapshotProof(t, restored, authz.CapabilityReviewEnquiry, "reviewer-23", "membership-23", at)
	expected, err := original.StartReview(proof, 1, at)
	if err != nil {
		t.Fatal(err)
	}
	review, err := restored.StartReview(proof, 1, at)
	if err != nil || review != expected {
		t.Fatalf("authorized review after restoration differed from original: %v", err)
	}
	restoredReview, err := enquiries.Restore(review.Enquiry.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	priorAudit := review.Audit
	result, err = restoredReview.Qualify(authz.EnquiryTransitionAuthorization{}, 2, at)
	if err != authz.ErrTransitionUnauthorized || result != (enquiries.TransitionResult{}) {
		t.Fatal("restoration conferred qualification authority")
	}
	beforeReview := at.Add(-time.Nanosecond)
	proof = snapshotProof(t, restoredReview, authz.CapabilityQualifyEnquiry, "reviewer-23", "membership-23", beforeReview)
	result, err = restoredReview.Qualify(proof, 2, beforeReview)
	if err != enquiries.ErrInvalidTransition || result != (enquiries.TransitionResult{}) {
		t.Fatal("restore lost last-change time or rounded its nanoseconds")
	}
	proof = snapshotProof(t, restoredReview, authz.CapabilityQualifyEnquiry, "reviewer-23", "membership-23", at)
	result, err = restoredReview.Qualify(proof, 1, at)
	if err != enquiries.ErrVersionConflict || result != (enquiries.TransitionResult{}) {
		t.Fatal("restore lost the expected-version boundary")
	}
	if restoredReview != review.Enquiry || review.Audit != priorAudit {
		t.Fatal("failed operations on restored state changed prior enquiry or audit")
	}
	expected, err = review.Enquiry.Qualify(proof, 2, at)
	if err != nil {
		t.Fatal(err)
	}
	qualified, err := restoredReview.Qualify(proof, 2, at)
	if err != nil || qualified != expected {
		t.Fatalf("authorized qualification after restoration differed from original: %v", err)
	}
}
