package enquiries

import (
	"errors"
	"time"
)

// ErrInvalidSnapshot never exposes stored input or identity values.
var ErrInvalidSnapshot = errors.New("invalid enquiry snapshot")

// Snapshot is a detached storage value for a trusted future persistence adapter.
// It is not a request/transport type or evidence of authorization. Adapters must
// verify tenant-scoped references and audit history before calling Restore.
// Input contains private contact data; snapshots must not be logged as audit data.
type Snapshot struct {
	ID                   string
	OrganizationID       string
	State                State
	CreatedBy            string
	MembershipID         string
	CreatedAt            time.Time
	Input                Input
	AssigneeMembershipID string
	Version              uint64
	LastChangedAt        time.Time
}

// Snapshot exports a copy of all domain state without changing it or emitting an
// event. The zero enquiry exports a zero snapshot, which Restore rejects.
func (e Enquiry) Snapshot() Snapshot {
	return Snapshot{
		ID: e.id, OrganizationID: e.organizationID, State: e.state,
		CreatedBy: e.createdBy, MembershipID: e.membershipID, CreatedAt: e.createdAt,
		Input: e.input, AssigneeMembershipID: e.assigneeMembershipID,
		Version: e.version, LastChangedAt: e.lastChangedAt,
	}
}

// Restore reconstructs private state from trusted storage, not caller or AI
// claims. It checks only invariants contained in the snapshot: it cannot prove
// ownership/membership references, historical authorization, or an audit chain.
// It neither obtains current authority nor emits a creation/transition event.
// Revocation of a historical creator does not invalidate their attribution.
// Instants retain nanosecond precision and are represented in UTC, as in New.
func Restore(snapshot Snapshot) (Enquiry, error) {
	if !validID(snapshot.ID) || !validID(snapshot.OrganizationID) ||
		!validID(snapshot.CreatedBy) || !validID(snapshot.MembershipID) {
		return Enquiry{}, ErrInvalidSnapshot
	}
	createdAt, lastChangedAt := snapshot.CreatedAt.UTC(), snapshot.LastChangedAt.UTC()
	if ValidateInput(snapshot.Input, createdAt) != nil || lastChangedAt.IsZero() ||
		lastChangedAt.Year() < 1 || lastChangedAt.Year() > 9999 || lastChangedAt.Before(createdAt) {
		return Enquiry{}, ErrInvalidSnapshot
	}

	// These are the only combinations reachable through the current operations.
	// A future business operation must deliberately extend this boundary too.
	switch snapshot.State {
	case StateNew:
		if snapshot.Version != 1 || snapshot.AssigneeMembershipID != "" || !lastChangedAt.Equal(createdAt) {
			return Enquiry{}, ErrInvalidSnapshot
		}
	case StateUnderReview:
		if snapshot.Version != 2 || !validID(snapshot.AssigneeMembershipID) {
			return Enquiry{}, ErrInvalidSnapshot
		}
	case StateQualified:
		if snapshot.Version != 3 || !validID(snapshot.AssigneeMembershipID) {
			return Enquiry{}, ErrInvalidSnapshot
		}
	default:
		return Enquiry{}, ErrInvalidSnapshot
	}

	return Enquiry{
		id: snapshot.ID, organizationID: snapshot.OrganizationID, state: snapshot.State,
		createdBy: snapshot.CreatedBy, membershipID: snapshot.MembershipID, createdAt: createdAt,
		input: snapshot.Input, assigneeMembershipID: snapshot.AssigneeMembershipID,
		version: snapshot.Version, lastChangedAt: lastChangedAt,
	}, nil
}
