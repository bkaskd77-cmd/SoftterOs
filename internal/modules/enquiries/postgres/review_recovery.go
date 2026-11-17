package postgres

import (
	"context"
	"crypto/hmac"
	"errors"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	// Unconfirmed describes this lookup, never proof that the original write rolled back.
	ErrReviewUnconfirmed = errors.New("enquiry review completion unconfirmed")
	ErrReviewMismatch    = errors.New("enquiry review request does not match receipt")
)

// Recover returns only the historical StartReview acknowledgement, under fresh
// authority for the same actor, organization and membership. A completed event
// also requires its original grant to remain the sole eligible review grant.
// It never checks current state/assignment, invokes the transition, or writes.
func (r *ReviewStarter) Recover(ctx context.Context, request ReviewRequest, enquiryID string, expectedVersion uint64, requestKey string) (StartedReview, error) {
	if r == nil || r.db == nil || r.identity == nil {
		return StartedReview{}, ErrReviewConfiguration
	}
	if !identifier(request.ActorID) || !identifier(request.OrganizationID) ||
		!identifier(request.MembershipID) || !identifier(request.RequestID) {
		return StartedReview{}, authz.ErrTransitionUnauthorized
	}
	if !identifier(enquiryID) || !identifier(requestKey) || expectedVersion != 1 {
		return StartedReview{}, ErrSelector
	}
	var candidate StartedReview
	err := r.db.WithTx(ctx, pg.Scope{ActorID: request.ActorID, OrganizationID: request.OrganizationID}, func(ctx context.Context, tx pg.Executor) error {
		facts, err := r.currentAuthority(ctx, tx, request)
		if err != nil {
			return err
		}
		proof, err := facts.authorize(ctx, tx, request.OrganizationID, enquiryID)
		if err != nil {
			return err
		}
		fingerprint, err := reviewFingerprint(r.secret, proof, enquiryID, requestKey)
		if err != nil {
			return err
		}
		var receipt reviewReceipt
		err = tx.QueryRow(ctx, recoverReviewSQL, proof.OrganizationID(), proof.MembershipID(), requestKey,
			proof.ActorID(), enquiryID, string(authz.CapabilityReviewEnquiry)).Scan(
			&receipt.enquiryID, &receipt.eventID, &receipt.command, &receipt.expectedVersion, &receipt.resultingVersion,
			&receipt.fingerprintVersion, &receipt.fingerprint, &receipt.completed, &receipt.completedAt,
			&receipt.at, &receipt.grantID, &receipt.assignee, &receipt.resourceMatches)
		var outcome error
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			outcome = ErrReviewUnconfirmed
		case err != nil:
			return errors.Join(ErrStorage, ctx.Err())
		default:
			candidate, outcome = receipt.acknowledgement(proof, enquiryID, fingerprint)
		}
		// Receipt resolution/validation can take time. Recheck even a mismatch
		// or unconfirmed result before releasing receipt-dependent information.
		if _, err := facts.authorize(ctx, tx, request.OrganizationID, enquiryID); err != nil {
			return err
		}
		return outcome
	})
	if err != nil {
		return StartedReview{}, err
	}
	return candidate, nil
}

type reviewReceipt struct {
	enquiryID, eventID, grantID, assignee pgtype.Text
	command                               string
	expectedVersion                       int64
	resultingVersion                      pgtype.Int8
	fingerprintVersion                    int16
	fingerprint                           []byte
	completed                             bool
	completedAt, at                       pgtype.Timestamptz
	resourceMatches                       bool
}

func (r reviewReceipt) acknowledgement(a authz.EnquiryTransitionAuthorization, enquiryID string, fingerprint [32]byte) (StartedReview, error) {
	if r.command != "enquiry.review_started" || r.expectedVersion != 1 ||
		r.fingerprintVersion != 1 || len(r.fingerprint) != len(fingerprint) ||
		!r.enquiryID.Valid || !identifier(r.enquiryID.String) || r.enquiryID.String != enquiryID || !r.resourceMatches {
		return StartedReview{}, ErrStored
	}
	if !r.completed {
		// Unlike creation, a review reservation already binds its enquiry.
		// It has no completion fields or original event/grant yet.
		if r.eventID != (pgtype.Text{}) || r.resultingVersion != (pgtype.Int8{}) ||
			r.completedAt != (pgtype.Timestamptz{}) || r.at != (pgtype.Timestamptz{}) ||
			r.grantID != (pgtype.Text{}) || r.assignee != (pgtype.Text{}) {
			return StartedReview{}, ErrStored
		}
	} else {
		if !r.eventID.Valid || !identifier(r.eventID.String) || !r.grantID.Valid || !identifier(r.grantID.String) ||
			!r.assignee.Valid || r.assignee.String != a.MembershipID() ||
			!r.resultingVersion.Valid || r.resultingVersion.Int64 != 2 ||
			!instant(r.at) || !instant(r.completedAt) || r.completedAt.Time.Before(r.at.Time) {
			return StartedReview{}, ErrStored
		}
		// A structurally valid historical grant may have lost current authority.
		// A different current grant does not make that history corrupt or readable.
		if r.grantID.String != a.GrantID() {
			return StartedReview{}, authz.ErrTransitionUnauthorized
		}
	}
	if !hmac.Equal(r.fingerprint, fingerprint[:]) {
		return StartedReview{}, ErrReviewMismatch
	}
	if !r.completed {
		return StartedReview{}, ErrReviewUnconfirmed
	}
	return StartedReview{OrganizationID: a.OrganizationID(), EnquiryID: r.enquiryID.String, EventID: r.eventID.String,
		State: enquiries.StateUnderReview, Version: 2, AssigneeMembershipID: r.assignee.String, At: r.at.Time.UTC()}, nil
}

// One statement snapshot verifies only immutable command/event/resource facts.
// An inaccessible target is absent; a NULL target is included to reject malformed
// review metadata. LEFT JOIN keeps broken event bindings visible as corruption.
// No current state/version/assignment or private enquiry input is selected.
const recoverReviewSQL = `SELECT r.enquiry_id::text,r.event_id::text,r.command,r.expected_version,r.resulting_version,
 r.fingerprint_version,r.fingerprint,r.completed,r.completed_at::timestamptz,
 v.at::timestamptz,v.grant_id::text,v.assignee_membership_id::text,
 EXISTS(SELECT 1 FROM softteros_enquiries.enquiries e
   WHERE e.organization_id=r.organization_id AND e.enquiry_id=r.enquiry_id
     AND (v.at IS NULL OR e.created_at<=v.at))
FROM softteros_enquiries.enquiry_command_receipts r
LEFT JOIN softteros_enquiries.enquiry_events v
 ON v.organization_id=r.organization_id AND v.event_id=r.event_id AND v.enquiry_id=r.enquiry_id
 AND v.active_organization_id=r.organization_id AND v.actor_id=r.actor_id AND v.membership_id=r.membership_id
 AND v.request_key=r.request_key AND v.action=r.command AND v.resulting_version=r.resulting_version
 AND v.capability=$6 AND v.outcome='success' AND v.previous_state='New' AND v.new_state='Under review'
 AND v.previous_version=1 AND v.resulting_version=2 AND v.previous_assignee_membership_id IS NULL
 AND v.assignee_membership_id=r.membership_id AND v.actor_authority_revision>0 AND v.organization_authority_revision>0
 AND EXISTS(SELECT 1 FROM softteros_access.enquiry_transition_grants g
   WHERE g.organization_id=v.organization_id AND g.grant_id=v.grant_id AND g.enquiry_id=v.enquiry_id
     AND g.actor_id=v.actor_id AND g.membership_id=v.membership_id AND g.capability=v.capability)
WHERE r.organization_id=$1 AND r.membership_id=$2 AND r.request_key=$3 AND r.actor_id=$4
 AND r.command='enquiry.review_started' AND (r.enquiry_id=$5 OR r.enquiry_id IS NULL)
 AND softteros_access.context_organization()=$1 AND softteros_access.context_actor()=$4`
