package postgres

import (
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	"github.com/jackc/pgx/v5/pgtype"
)

// Decoded storage types stay entirely outside the domain. Reference booleans are
// evidence from the same tenant-qualified statement, not current permissions.
type storedEnquiry struct {
	OrganizationID, ID, State, CreatedBy, MembershipID string
	Input                                              enquiries.Input
	Start, End                                         pgtype.Date
	Created, Changed                                   pgtype.Timestamptz
	Assignee                                           pgtype.Text
	Version                                            int64
	CreatorReference, AssigneeReference                bool
}

type storedEvent struct {
	OrganizationID, ID, EnquiryID, RequestKey, ActiveOrganizationID string
	ActorID, MembershipID, Action, Capability, Outcome              string
	Grant, PreviousState, PreviousAssignee, Assignee                pgtype.Text
	NewState                                                        string
	PreviousVersion                                                 pgtype.Int8
	Version, ActorRevision, OrganizationRevision                    int64
	At                                                              pgtype.Timestamptz
	MemberReference, GrantReference, ReceiptReference               bool
}

func restore(r storedEnquiry, events []storedEvent, org, id string) (Loaded, error) {
	bad := func() (Loaded, error) { return Loaded{}, ErrStored }
	if r.OrganizationID != org || r.ID != id || r.Version < 1 || r.Version > 3 ||
		int64(len(events)) != r.Version || !r.CreatorReference || !r.AssigneeReference ||
		!instant(r.Created) || !instant(r.Changed) || !optionalID(r.Assignee) {
		return bad()
	}
	start, okStart := calendar(r.Start)
	end, okEnd := calendar(r.End)
	if !okStart || !okEnd {
		return bad()
	}
	input := r.Input
	input.TravelStart, input.TravelEnd = start, end
	snapshot := enquiries.Snapshot{
		ID: id, OrganizationID: org, State: enquiries.State(r.State), CreatedBy: r.CreatedBy,
		MembershipID: r.MembershipID, CreatedAt: r.Created.Time.UTC(), LastChangedAt: r.Changed.Time.UTC(),
		Input: input, AssigneeMembershipID: r.Assignee.String, Version: uint64(r.Version),
	}
	enquiry, err := enquiries.Restore(snapshot)
	if err != nil {
		return bad()
	}
	var transitions []enquiries.TransitionAudit
	var previousTime time.Time
	for i, e := range events {
		version := int64(i + 1)
		if e.Version != version || e.OrganizationID != org || e.ActiveOrganizationID != org || e.EnquiryID != id ||
			!identifier(e.ID) || !identifier(e.RequestKey) || !identifier(e.ActorID) || !identifier(e.MembershipID) ||
			e.Outcome != "success" || e.ActorRevision <= 0 || e.OrganizationRevision <= 0 ||
			!e.MemberReference || !e.GrantReference || !e.ReceiptReference || !instant(e.At) ||
			(i > 0 && e.At.Time.Before(previousTime)) || !optionalID(e.Grant) ||
			!optionalID(e.PreviousAssignee) || !optionalID(e.Assignee) {
			return bad()
		}
		for j := 0; j < i; j++ {
			if events[j].ID == e.ID || (events[j].MembershipID == e.MembershipID && events[j].RequestKey == e.RequestKey) {
				return bad()
			}
		}
		switch version {
		case 1:
			if e.Action != "enquiry.created" || e.Capability != string(authz.CapabilityCreateEnquiry) ||
				e.Grant.Valid || e.PreviousState.Valid || e.PreviousVersion.Valid ||
				e.PreviousAssignee.Valid || e.Assignee.Valid || e.NewState != string(enquiries.StateNew) ||
				e.ActorID != r.CreatedBy || e.MembershipID != r.MembershipID || !e.At.Time.Equal(r.Created.Time) {
				return bad()
			}
		case 2, 3:
			from, to, action, capability := enquiries.StateNew, enquiries.StateUnderReview, "enquiry.review_started", authz.CapabilityReviewEnquiry
			if version == 3 {
				from, to, action, capability = enquiries.StateUnderReview, enquiries.StateQualified, "enquiry.qualified", authz.CapabilityQualifyEnquiry
			}
			if e.Action != action || e.Capability != string(capability) || !e.Grant.Valid ||
				!e.PreviousState.Valid || e.PreviousState.String != string(from) || e.NewState != string(to) ||
				!e.PreviousVersion.Valid || e.PreviousVersion.Int64 != version-1 ||
				!e.Assignee.Valid || e.Assignee.String != e.MembershipID || e.Assignee != r.Assignee ||
				(version == 2 && e.PreviousAssignee.Valid) || (version == 3 && e.PreviousAssignee != e.Assignee) {
				return bad()
			}
			transitions = append(transitions, enquiries.TransitionAudit{
				Action: e.Action, OrganizationID: org, ActiveOrganizationID: e.ActiveOrganizationID, EnquiryID: id,
				PreviousState: from, NewState: to, ActorID: e.ActorID, MembershipID: e.MembershipID,
				GrantID: e.Grant.String, Capability: capability, PreviousAssigneeMembershipID: e.PreviousAssignee.String,
				AssigneeMembershipID: e.Assignee.String, PreviousVersion: uint64(e.PreviousVersion.Int64),
				Version: uint64(e.Version), At: e.At.Time.UTC(),
			})
		}
		previousTime = e.At.Time
	}
	last := events[len(events)-1]
	if last.NewState != r.State || !last.At.Time.Equal(r.Changed.Time) {
		return bad()
	}
	return Loaded{Enquiry: enquiry, Transitions: transitions}, nil
}

// No truncation, rounding, infinity, zero sentinel, or range coercion is allowed.
func instant(t pgtype.Timestamptz) bool {
	u := t.Time.UTC()
	return t.Valid && t.InfinityModifier == pgtype.Finite && !u.IsZero() && u.Year() >= 1 && u.Year() <= 9999 && u.Nanosecond()%1000 == 0
}

func calendar(d pgtype.Date) (string, bool) {
	if !d.Valid {
		return "", d.Time.IsZero() && d.InfinityModifier == pgtype.Finite
	}
	y, m, day := d.Time.Date()
	if d.InfinityModifier != pgtype.Finite || y < 1 || y > 9999 ||
		d.Time.Hour() != 0 || d.Time.Minute() != 0 || d.Time.Second() != 0 || d.Time.Nanosecond() != 0 {
		return "", false
	}
	// Calendar components, not UTC conversion of a location-dependent instant.
	return time.Date(y, m, day, 0, 0, 0, 0, time.UTC).Format("2006-01-02"), true
}

func optionalID(v pgtype.Text) bool {
	return (!v.Valid && v.String == "") || (v.Valid && identifier(v.String))
}

func identifier(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && (c == '_' || c == '-') {
			continue
		}
		return false
	}
	return true
}
