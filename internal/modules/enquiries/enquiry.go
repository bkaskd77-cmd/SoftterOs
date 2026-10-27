// Package enquiries contains immutable manual enquiries and their bounded workflow.
package enquiries

import (
	"errors"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
)

// State identifies the enquiry's business state.
type State string

// StateNew is the only state accepted at creation.
const StateNew State = "New"

// ErrInvalidID is returned without echoing a caller-supplied identifier.
var ErrInvalidID = errors.New("invalid enquiry identifier")

// Enquiry is an immutable value. Its zero value is not a created enquiry.
// Ownership and attribution can only enter through an authorization grant.
type Enquiry struct {
	id                   string
	organizationID       string
	state                State
	createdBy            string
	membershipID         string
	createdAt            time.Time
	input                Input
	assigneeMembershipID string
	version              uint64
	lastChangedAt        time.Time
}

// New creates an enquiry in memory from a grant issued for this operation.
// It neither persists a record nor emits a durable audit event. Callers must
// obtain fresh authorization from trusted facts immediately before creation.
func New(id string, input Input, authorization authz.CreationAuthorization) (Enquiry, error) {
	if !authorization.Valid() {
		return Enquiry{}, authz.ErrUnauthorized
	}
	if !validID(id) {
		return Enquiry{}, ErrInvalidID
	}
	createdAt := authorization.AuthorizedAt().UTC()
	if err := ValidateInput(input, createdAt); err != nil {
		return Enquiry{}, err
	}
	return Enquiry{
		id:             id,
		organizationID: authorization.OrganizationID(),
		state:          StateNew,
		createdBy:      authorization.ActorID(),
		membershipID:   authorization.MembershipID(),
		createdAt:      createdAt,
		input:          input,
		version:        1,
		lastChangedAt:  createdAt,
	}, nil
}

// ID returns the identifier supplied by the trusted identifier generator.
func (e Enquiry) ID() string { return e.id }

// OrganizationID returns the authoritative owning organization.
func (e Enquiry) OrganizationID() string { return e.organizationID }

// State returns the enquiry's business state.
func (e Enquiry) State() State { return e.state }

// CreatedBy returns the authenticated creator's actor identifier.
func (e Enquiry) CreatedBy() string { return e.createdBy }

// CreatedAt returns the authorization and creation instant in UTC.
func (e Enquiry) CreatedAt() time.Time { return e.createdAt }

// MembershipID returns the membership used to authorize creation.
func (e Enquiry) MembershipID() string { return e.membershipID }

// Input returns a copy of the captured input; modifying it cannot change e.
func (e Enquiry) Input() Input { return e.input }

// CreationAudit contains attributable facts for a successful creation. It omits
// contact details and travel input. A future persistence boundary must commit
// these facts atomically with the enquiry; returning them is not durable logging.
type CreationAudit struct {
	Action         string
	EnquiryID      string
	OrganizationID string
	ActorID        string
	MembershipID   string
	At             time.Time
	Capability     authz.Capability
}

// CreationAudit returns an independent value. An uncreated enquiry has no event.
func (e Enquiry) CreationAudit() CreationAudit {
	if e.id == "" {
		return CreationAudit{}
	}
	return CreationAudit{
		Action:         "enquiry.created",
		EnquiryID:      e.id,
		OrganizationID: e.organizationID,
		ActorID:        e.createdBy,
		MembershipID:   e.membershipID,
		At:             e.createdAt,
		Capability:     authz.CapabilityCreateEnquiry,
	}
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if i > 0 && (c == '_' || c == '-') {
			continue
		}
		return false
	}
	return true
}
