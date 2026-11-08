package postgres

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
)

const reviewFingerprintTag = "softteros.enquiry.start_review.fingerprint.v1"

// Version 1 binds only the approved command fields. The immutable event
// records the actual grant, revisions and action time.
func canonicalReview(a authz.EnquiryTransitionAuthorization, enquiryID, requestKey string) ([]byte, error) {
	if !a.ValidFor(enquiryID, a.OrganizationID(), authz.CapabilityReviewEnquiry, a.AuthorizedAt()) {
		return nil, authz.ErrTransitionUnauthorized
	}
	if !identifier(requestKey) {
		return nil, ErrSelector
	}
	return frameCreationFields([]string{
		reviewFingerprintTag, a.OrganizationID(), a.ActorID(), a.MembershipID(), requestKey,
		"enquiry.review_started", enquiryID, "1",
	})
}

func reviewFingerprint(secret [32]byte, a authz.EnquiryTransitionAuthorization, enquiryID, requestKey string) ([32]byte, error) {
	var result [32]byte
	canonical, err := canonicalReview(a, enquiryID, requestKey)
	if err != nil {
		return result, err
	}
	mac := hmac.New(sha256.New, secret[:])
	mac.Write(canonical)
	copy(result[:], mac.Sum(nil))
	return result, nil
}
