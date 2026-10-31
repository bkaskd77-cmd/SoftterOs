// Package postgres loads historical enquiry values for trusted internal callers.
// It does not authenticate or authorize business access, or persist commands.
package postgres

import (
	"context"
	"errors"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
)

var (
	ErrSelector = errors.New("invalid enquiry storage selector")
	ErrNotFound = errors.New("enquiry unavailable")
	ErrStored   = errors.New("invalid stored enquiry")
	ErrStorage  = errors.New("enquiry storage unavailable")
)

// Loaded contains detached historical facts, not newly emitted success events.
// Transitions are ordered by resulting version and never confer current authority.
type Loaded struct {
	Enquiry     enquiries.Enquiry
	Transitions []enquiries.TransitionAudit
}

// Load must run inside the existing DB.WithTx callback, after any required current
// authorization. tx is that callback's Executor, never a pool or an unscoped
// connection. The caller owns completion; this candidate must not escape if the
// surrounding transaction fails. No row locks or workflow writes are performed.
func Load(ctx context.Context, tx pg.Executor, organizationID, enquiryID string) (Loaded, error) {
	if !identifier(organizationID) || !identifier(enquiryID) || tx == nil {
		return Loaded{}, ErrSelector
	}
	rows, err := tx.Query(ctx, loadSQL, organizationID, enquiryID)
	if err != nil {
		return Loaded{}, ErrStorage
	}
	defer rows.Close()
	var record storedEnquiry
	var history []storedEvent
	for rows.Next() {
		var event storedEvent
		if len(history) == 3 {
			return Loaded{}, ErrStored
		}
		if err := rows.Scan(
			&record.OrganizationID, &record.ID, &record.Input.ContactName, &record.Input.ContactEmail,
			&record.Input.Destination, &record.Input.TravellerCount, &record.Start, &record.End,
			&record.State, &record.CreatedBy, &record.MembershipID, &record.Created,
			&record.Assignee, &record.Version, &record.Changed, &record.CreatorReference, &record.AssigneeReference,
			&event.OrganizationID, &event.ID, &event.EnquiryID, &event.RequestKey, &event.ActiveOrganizationID,
			&event.ActorID, &event.MembershipID, &event.Grant, &event.Action, &event.Capability, &event.Outcome,
			&event.ActorRevision, &event.OrganizationRevision, &event.PreviousState, &event.NewState,
			&event.PreviousAssignee, &event.Assignee, &event.PreviousVersion, &event.Version, &event.At,
			&event.MemberReference, &event.GrantReference, &event.ReceiptReference,
		); err != nil {
			// Includes a missing LEFT JOIN event, NULL in required fields, and
			// representations that cannot be decoded. Never echo driver values.
			return Loaded{}, ErrStored
		}
		history = append(history, event)
	}
	if rows.Err() != nil {
		return Loaded{}, ErrStorage
	}
	if len(history) == 0 {
		return Loaded{}, ErrNotFound
	}
	return restore(record, history, organizationID, enquiryID)
}

// One statement gives the row, references and complete history one MVCC snapshot
// even under READ COMMITTED. LEFT JOIN exposes missing history as corruption;
// explicit tenant predicates supplement, rather than replace, forced RLS.
const loadSQL = `
SELECT e.organization_id::text,e.enquiry_id::text,e.contact_name,e.contact_email,
 e.destination,e.traveller_count,e.travel_start,e.travel_end,e.state,
 e.created_by::text,e.creator_membership_id::text,e.created_at::timestamptz,
 e.assignee_membership_id::text,e.version,e.last_changed_at::timestamptz,
 EXISTS(SELECT 1 FROM softteros_access.memberships m WHERE m.organization_id=e.organization_id
   AND m.membership_id=e.creator_membership_id AND m.actor_id=e.created_by),
 (e.assignee_membership_id IS NULL OR EXISTS(SELECT 1 FROM softteros_access.memberships m
   WHERE m.organization_id=e.organization_id AND m.membership_id=e.assignee_membership_id)),
 v.organization_id::text,v.event_id::text,v.enquiry_id::text,v.request_key::text,
 v.active_organization_id::text,v.actor_id::text,v.membership_id::text,v.grant_id::text,
 v.action,v.capability,v.outcome,v.actor_authority_revision,v.organization_authority_revision,
 v.previous_state,v.new_state,v.previous_assignee_membership_id::text,
 v.assignee_membership_id::text,v.previous_version,v.resulting_version,v.at::timestamptz,
 EXISTS(SELECT 1 FROM softteros_access.memberships m WHERE m.organization_id=v.organization_id
   AND m.membership_id=v.membership_id AND m.actor_id=v.actor_id),
 (v.grant_id IS NULL OR EXISTS(SELECT 1 FROM softteros_access.enquiry_transition_grants g
   WHERE g.organization_id=v.organization_id AND g.grant_id=v.grant_id AND g.enquiry_id=v.enquiry_id
     AND g.actor_id=v.actor_id AND g.membership_id=v.membership_id AND g.capability=v.capability)),
 EXISTS(SELECT 1 FROM softteros_enquiries.enquiry_command_receipts r
   WHERE r.organization_id=v.organization_id AND r.membership_id=v.membership_id
     AND r.request_key=v.request_key AND r.actor_id=v.actor_id AND r.command=v.action
     AND r.enquiry_id=v.enquiry_id AND r.event_id=v.event_id AND r.resulting_version=v.resulting_version
     AND r.expected_version=v.resulting_version-1 AND r.completed AND r.completed_at>=v.at)
FROM softteros_enquiries.enquiries e
LEFT JOIN softteros_enquiries.enquiry_events v
 ON v.organization_id=e.organization_id AND v.enquiry_id=e.enquiry_id
WHERE e.organization_id=$1 AND e.enquiry_id=$2
 AND softteros_access.context_organization()=$1
ORDER BY v.resulting_version`
