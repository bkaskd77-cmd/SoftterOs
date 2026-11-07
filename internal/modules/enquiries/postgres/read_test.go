package postgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries/application"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
)

type readIdentityFunc func(context.Context, ReadIdentityRequest) (ReadAttestation, error)

func (f readIdentityFunc) CurrentEnquiryRead(ctx context.Context, request ReadIdentityRequest) (ReadAttestation, error) {
	return f(ctx, request)
}

type readBoundaryFunc func(context.Context, pg.Scope, func(context.Context, pg.Executor) error) error

func (f readBoundaryFunc) WithTx(ctx context.Context, scope pg.Scope, callback func(context.Context, pg.Executor) error) error {
	return f(ctx, scope, callback)
}

func TestAssignedViewStateAndFields(t *testing.T) {
	for _, tc := range []struct {
		state   enquiries.State
		version int64
		err     error
	}{
		{enquiries.StateUnderReview, 2, nil},
		{enquiries.StateQualified, 3, nil},
		{enquiries.StateNew, 1, application.ErrEnquiryUnavailable},
		{"Archived", 4, application.ErrEnquiryUnavailable},
		{"", 2, application.ErrEnquiryUnavailable},
		{enquiries.StateUnderReview, 3, ErrStored},
		{enquiries.StateQualified, -1, ErrStored},
	} {
		got, err := assignedView("enquiry-view", tc.state, tc.version)
		if err != tc.err {
			t.Fatalf("unexpected state/version outcome for %q/%d: %v", tc.state, tc.version, err)
		}
		want := application.EnquiryDetails{}
		if tc.err == nil {
			want = application.EnquiryDetails{EnquiryID: "enquiry-view", State: tc.state, Version: uint64(tc.version)}
		}
		if got != want {
			t.Fatal("unexpected or partial state/version view")
		}
	}
	var fields []string
	for _, f := range reflect.VisibleFields(reflect.TypeOf(application.EnquiryDetails{})) {
		fields = append(fields, f.Name)
	}
	if !reflect.DeepEqual(fields, []string{"EnquiryID", "State", "Version", "Destination", "TravellerCount", "TravelStart", "TravelEnd"}) {
		t.Fatal("assigned view field allowlist changed")
	}
}

func TestAssignedReadRejectsInvalidSelectorsBeforeTransaction(t *testing.T) {
	reader := &AssignedReader{
		db: readBoundaryFunc(func(context.Context, pg.Scope, func(context.Context, pg.Executor) error) error {
			t.Fatal("invalid read input opened a transaction")
			return nil
		}),
		identity: readIdentityFunc(func(context.Context, ReadIdentityRequest) (ReadAttestation, error) {
			t.Fatal("invalid read input requested an attestation")
			return ReadAttestation{}, nil
		}),
	}
	got, err := reader.GetEnquiry(context.Background(), application.ReadRequest{}, "valid-id")
	if err != application.ErrEnquiryUnavailable || got != (application.EnquiryDetails{}) {
		t.Fatal("missing scope did not deny with an empty view", err)
	}
	request := application.ReadRequest{ActorID: "actor-read", OrganizationID: "org-read", MembershipID: "member-read", RequestID: "request-read"}
	got, err = reader.GetEnquiry(context.Background(), request, "invalid selector")
	if err != application.ErrInvalidEnquiryID || got != (application.EnquiryDetails{}) {
		t.Fatal("malformed selector did not fail safely", err)
	}
}

func TestAssignedReadOperationalErrorsAreSanitized(t *testing.T) {
	private := errors.New("private fixture diagnostics")
	err := safeReadError(context.Background(), errors.Join(application.ErrEnquiryUnavailable, pg.ErrCleanup, private))
	if !errors.Is(err, application.ErrEnquiryReadFailed) || !errors.Is(err, pg.ErrCleanup) ||
		errors.Is(err, application.ErrEnquiryUnavailable) || strings.Contains(err.Error(), private.Error()) {
		t.Fatal("cleanup failure was hidden or exposed private diagnostics")
	}
}
