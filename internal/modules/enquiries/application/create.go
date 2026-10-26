// Package application coordinates the manual enquiry creation boundary.
// It returns a new value and attributable audit facts; it does not persist them.
package application

import (
	"errors"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
)

var (
	ErrConfiguration        = errors.New("enquiry creator is not configured")
	ErrIdentifierGeneration = errors.New("could not create enquiry identifier")
)

// Creator uses a trusted server clock and identifier generator. Dependencies
// must be safe for their intended concurrency and must not use request-supplied
// time or identifiers. A future persistence boundary must enforce ID uniqueness.
type Creator struct {
	now   func() time.Time
	newID func() (string, error)
}

func NewCreator(now func() time.Time, newID func() (string, error)) (Creator, error) {
	if now == nil || newID == nil {
		return Creator{}, ErrConfiguration
	}
	return Creator{now: now, newID: newID}, nil
}

// Result contains independent values. A future persistence adapter must save
// the enquiry and its audit facts atomically, after rechecking current access.
// A successful call alone is not a durable save or an audit-log write.
type Result struct {
	Enquiry enquiries.Enquiry
	Audit   enquiries.CreationAudit
}

// Create checks authorization before inspecting enquiry input or generating an
// identifier. Ownership, initial state, attribution, and creation time cannot be
// supplied through Input. Every failure returns an empty result.
func (c Creator) Create(context authz.Context, input enquiries.Input) (Result, error) {
	if c.now == nil || c.newID == nil {
		return Result{}, ErrConfiguration
	}

	authorization, err := context.AuthorizeEnquiryCreation(c.now())
	if err != nil {
		return Result{}, err
	}
	if err := enquiries.ValidateInput(input, authorization.AuthorizedAt()); err != nil {
		return Result{}, err
	}

	id, err := c.newID()
	if err != nil {
		// Do not leak infrastructure details from a future identifier provider.
		return Result{}, ErrIdentifierGeneration
	}
	enquiry, err := enquiries.New(id, input, authorization)
	if err != nil {
		return Result{}, err
	}
	return Result{Enquiry: enquiry, Audit: enquiry.CreationAudit()}, nil
}
