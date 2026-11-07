package application

import (
	"errors"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
)

var (
	ErrInvalidEnquiryID   = errors.New("invalid enquiry identifier")
	ErrEnquiryUnavailable = errors.New("enquiry unavailable")
	ErrEnquiryReadFailed  = errors.New("enquiry read failed")
)

// ReadRequest comes from trusted entry code that has authenticated the actor
// and bound the request ID. The selected organization and membership must
// still be verified against current authoritative facts.
type ReadRequest struct {
	ActorID, OrganizationID, MembershipID, RequestID string
}

// EnquiryDetails is the assigned-work view. Travel dates are both empty or
// calendar dates in YYYY-MM-DD format. No result accompanies a failed read.
type EnquiryDetails struct {
	EnquiryID      string
	State          enquiries.State
	Version        uint64
	Destination    string
	TravellerCount int
	TravelStart    string
	TravelEnd      string
}
