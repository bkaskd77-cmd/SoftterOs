package application

import (
	"errors"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
)

var ErrWorkflowConfiguration = errors.New("enquiry workflow is not configured")

// Workflow uses a trusted server clock and fresh verified context. It returns
// immutable values, not a durable save. Future persistence must atomically compare
// the stored version, recheck current authority, and commit state plus audit facts.
type Workflow struct {
	now func() time.Time
}

func NewWorkflow(now func() time.Time) (Workflow, error) {
	if now == nil {
		return Workflow{}, ErrWorkflowConfiguration
	}
	return Workflow{now: now}, nil
}

func (w Workflow) StartReview(context authz.Context, enquiry enquiries.Enquiry, expectedVersion uint64) (enquiries.TransitionResult, error) {
	return w.transition(context, enquiry, expectedVersion, authz.CapabilityReviewEnquiry)
}

func (w Workflow) Qualify(context authz.Context, enquiry enquiries.Enquiry, expectedVersion uint64) (enquiries.TransitionResult, error) {
	return w.transition(context, enquiry, expectedVersion, authz.CapabilityQualifyEnquiry)
}

func (w Workflow) transition(context authz.Context, enquiry enquiries.Enquiry, expectedVersion uint64, capability authz.Capability) (enquiries.TransitionResult, error) {
	if w.now == nil {
		return enquiries.TransitionResult{}, ErrWorkflowConfiguration
	}
	at := w.now()
	authorization, err := context.AuthorizeEnquiryTransition(enquiry.ID(), enquiry.OrganizationID(), capability, at)
	if err != nil {
		return enquiries.TransitionResult{}, err
	}
	if capability == authz.CapabilityReviewEnquiry {
		return enquiry.StartReview(authorization, expectedVersion, at)
	}
	return enquiry.Qualify(authorization, expectedVersion, at)
}
