package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
)

type reviewIdentityFunc func(context.Context, ReviewIdentityRequest) (ReviewAttestation, error)

func (f reviewIdentityFunc) CurrentEnquiryReview(ctx context.Context, request ReviewIdentityRequest) (ReviewAttestation, error) {
	return f(ctx, request)
}

func reviewProof(t *testing.T, org, actor, member, enquiry, grant string, capability authz.Capability, at time.Time) authz.EnquiryTransitionAuthorization {
	t.Helper()
	policy := authz.NewContext(authz.ContextInput{
		Actor: authz.Actor{ID: actor, Authenticated: true, Human: true}, ActiveOrganizationID: org,
		Membership: authz.Membership{
			ID: member, ActorID: actor, OrganizationID: org, Active: true,
			ValidFrom: created.Add(-time.Hour), ValidUntil: created.Add(time.Hour), Capabilities: []authz.Capability{capability},
		},
		TransitionGrant: authz.EnquiryTransitionGrant{
			ID: grant, ActorID: actor, MembershipID: member, OrganizationID: org, EnquiryID: enquiry, Capability: capability,
			Active: true, ValidFrom: created.Add(-time.Hour), ValidUntil: created.Add(time.Hour),
		},
	})
	proof, err := policy.AuthorizeEnquiryTransition(enquiry, org, capability, at)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestReviewFingerprintIndependentVectors(t *testing.T) {
	// Independent byte prefixes and .NET HMACSHA256 with the public vector key.
	for _, v := range []struct {
		org, actor, member, key, enquiry string
		frame, mac                       string
	}{
		{"org-29", "actor-17", "member-31", "key-59", "enquiry-71",
			"0000002d736f66747465726f732e656e71756972792e73746172745f7265766965772e66696e6765727072696e742e7631000000066f72672d3239000000086163746f722d3137000000096d656d6265722d3331000000066b65792d353900000016656e71756972792e7265766965775f737461727465640000000a656e71756972792d37310000000131",
			"8e61c02ef73b95a647bc00e140d0a7981878db66cc9419bbcca267fc256f9e0c"},
		{"A", "bC", "Ab_4", "X-3", "Enq_A-9",
			"0000002d736f66747465726f732e656e71756972792e73746172745f7265766965772e66696e6765727072696e742e763100000001410000000262430000000441625f3400000003582d3300000016656e71756972792e7265766965775f7374617274656400000007456e715f412d390000000131",
			"7a6eb70acdabf2a73886247689e5f5f29bd56430dc5438470ba4a10e3389119c"},
	} {
		t.Run(v.enquiry, func(t *testing.T) {
			proof := reviewProof(t, v.org, v.actor, v.member, v.enquiry, "grant-1", authz.CapabilityReviewEnquiry, created)
			frame, err := canonicalReview(proof, v.enquiry, v.key)
			if err != nil || hex.EncodeToString(frame) != v.frame {
				t.Fatal("review canonical bytes differ from independent vector", err)
			}
			mac, err := reviewFingerprint(vectorKey(), proof, v.enquiry, v.key)
			if err != nil || hex.EncodeToString(mac[:]) != v.mac {
				t.Fatal("review MAC differs from independent vector", err)
			}
		})
	}
}

func TestReviewFingerprintExclusionsAndBindings(t *testing.T) {
	first := reviewProof(t, "org-29", "actor-17", "member-31", "enquiry-71", "grant-1", authz.CapabilityReviewEnquiry, created)
	second := reviewProof(t, "org-29", "actor-17", "member-31", "enquiry-71", "grant-2", authz.CapabilityReviewEnquiry, created.Add(time.Minute))
	base, err := reviewFingerprint(vectorKey(), first, "enquiry-71", "key-59")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reviewFingerprint(vectorKey(), second, "enquiry-71", "key-59"); err != nil || got != base {
		t.Fatal("grant or action time changed the command fingerprint", err)
	}
	for _, args := range [][5]string{
		{"Org-29", "actor-17", "member-31", "enquiry-71", "key-59"},
		{"org-29", "actor-18", "member-31", "enquiry-71", "key-59"},
		{"org-29", "actor-17", "member-32", "enquiry-71", "key-59"},
		{"org-29", "actor-17", "member-31", "enquiry-72", "key-59"},
		{"org-29", "actor-17", "member-31", "enquiry-71", "key-60"},
	} {
		proof := reviewProof(t, args[0], args[1], args[2], args[3], "grant-1", authz.CapabilityReviewEnquiry, created)
		if got, err := reviewFingerprint(vectorKey(), proof, args[3], args[4]); err != nil || got == base {
			t.Fatal("a command field did not bind the MAC", err)
		}
	}
	qualify := reviewProof(t, "org-29", "actor-17", "member-31", "enquiry-71", "grant-1", authz.CapabilityQualifyEnquiry, created)
	for _, tc := range []struct {
		proof      authz.EnquiryTransitionAuthorization
		enquiryKey string
		requestKey string
		want       error
	}{
		{first, "enquiry-71", "\xff", ErrSelector},
		{first, "enquiry-72", "key-59", authz.ErrTransitionUnauthorized},
		{qualify, "enquiry-71", "key-59", authz.ErrTransitionUnauthorized},
		{authz.EnquiryTransitionAuthorization{}, "enquiry-71", "key-59", authz.ErrTransitionUnauthorized},
	} {
		if got, err := reviewFingerprint(vectorKey(), tc.proof, tc.enquiryKey, tc.requestKey); got != [32]byte{} || err != tc.want {
			t.Fatal("invalid review command was fingerprinted", err)
		}
	}
}

func TestStartReviewConfigurationAndSelectors(t *testing.T) {
	ctx := context.Background()
	request := ReviewRequest{"actor-17", "org-29", "member-31", "request-43"}
	identity := reviewIdentityFunc(func(context.Context, ReviewIdentityRequest) (ReviewAttestation, error) {
		t.Fatal("invalid request reached attestation")
		return ReviewAttestation{}, nil
	})
	id := func() (string, error) {
		t.Fatal("invalid request reached event generation")
		return "", nil
	}
	for _, size := range []int{0, 31, 33} {
		if r, err := NewReviewStarter(&pg.DB{}, identity, make([]byte, size), id); r != nil || err != ErrReviewConfiguration {
			t.Fatal("invalid review key accepted")
		}
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	r, err := NewReviewStarter(&pg.DB{}, identity, key[:], id)
	if err != nil {
		t.Fatal(err)
	}
	original := key
	key[0] ^= 1
	if r.secret != original {
		t.Fatal("review key was not copied")
	}
	if got, err := r.StartReview(ctx, ReviewRequest{}, "enquiry-71", 1, "key-59"); got != (StartedReview{}) || err != authz.ErrTransitionUnauthorized {
		t.Fatal("missing scope accepted", err)
	}
	for _, args := range [][2]string{{"enquiry with spaces", "key-59"}, {"enquiry-71", "bad key"}} {
		if got, err := r.StartReview(ctx, request, args[0], 1, args[1]); got != (StartedReview{}) || err != ErrSelector {
			t.Fatal("invalid selector accepted", err)
		}
	}
}
