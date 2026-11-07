package postgres

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
)

func captureInput() enquiries.Input {
	return enquiries.Input{ContactName: "Example Contact", ContactEmail: "contact@example.com", Destination: "Norway", TravellerCount: 2, TravelStart: "2020-02-29", TravelEnd: "2020-03-02"}
}

func fingerprintAuthority(t *testing.T, org, actor, member string, at time.Time) authz.CreationAuthorization {
	t.Helper()
	a, err := authz.NewContext(authz.ContextInput{Actor: authz.Actor{ID: actor, Authenticated: true}, ActiveOrganizationID: org,
		Membership: authz.Membership{ID: member, ActorID: actor, OrganizationID: org, Active: true,
			ValidFrom: created.Add(-time.Hour), ValidUntil: created.Add(time.Hour), Capabilities: []authz.Capability{authz.CapabilityCreateEnquiry}}}).AuthorizeEnquiryCreation(at)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// Public deterministic vector key ONLY. Expected frames were independently
// assembled as hexadecimal byte lengths and MACs checked with .NET HMACSHA256.
func vectorKey() (key [32]byte) {
	for i := range key {
		key[i] = byte(i)
	}
	return
}

func TestCreationFingerprintIndependentVectors(t *testing.T) {
	for _, v := range []struct {
		name       string
		input      enquiries.Input
		frame, mac string
	}{
		{"ascii", captureInput(),
			"00000027736f66747465726f732e656e71756972792e6372656174652e66696e6765727072696e742e7631000000066f72672d3239000000086163746f722d3137000000096d656d6265722d3331000000066b65792d35390000000f656e71756972792e6372656174656400000001300000000f4578616d706c6520436f6e7461637400000013636f6e74616374406578616d706c652e636f6d000000064e6f7277617900000001320000000a323032302d30322d32390000000a323032302d30332d3032",
			"320cbd4b3aaecce5c171f3aafd393e546b9522cd3997170cdf61f74f408404da"},
		{"unicode", enquiries.Input{ContactName: "Zoë", ContactEmail: "zoe@example.com", Destination: "東京", TravellerCount: 9},
			"00000027736f66747465726f732e656e71756972792e6372656174652e66696e6765727072696e742e7631000000066f72672d3239000000086163746f722d3137000000096d656d6265722d3331000000066b65792d35390000000f656e71756972792e637265617465640000000130000000045a6fc3ab0000000f7a6f65406578616d706c652e636f6d00000006e69db1e4baac00000001390000000000000000",
			"c892cca8e8d58e5c8225f4364409c6deabdc5c6e0fa9a7f8c28f731b4c8ba1f1"},
	} {
		t.Run(v.name, func(t *testing.T) {
			a := fingerprintAuthority(t, "org-29", "actor-17", "member-31", created)
			frame, err := canonicalCreation(a, "key-59", v.input)
			if err != nil || hex.EncodeToString(frame) != v.frame {
				t.Fatalf("canonical bytes differ from independent vector: %v", err)
			}
			mac, err := creationFingerprint(vectorKey(), a, "key-59", v.input)
			if err != nil || hex.EncodeToString(mac[:]) != v.mac {
				t.Fatalf("MAC differs from independent vector: %v", err)
			}
		})
	}
}

func TestCreationFingerprintCoverageAndExactValues(t *testing.T) {
	// Adding an input field requires an explicit fingerprint-contract decision.
	typ := reflect.TypeOf(enquiries.Input{})
	fields := []string{"ContactName", "ContactEmail", "Destination", "TravellerCount", "TravelStart", "TravelEnd"}
	if typ.NumField() != len(fields) {
		t.Fatal("enquiry input coverage changed")
	}
	for i, name := range fields {
		if typ.Field(i).Name != name {
			t.Fatal("input coverage changed")
		}
	}
	a := fingerprintAuthority(t, "org-29", "actor-17", "member-31", created)
	base, err := creationFingerprint(vectorKey(), a, "key-59", captureInput())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range append(fields, "organization", "actor", "membership", "request key") {
		t.Run(field, func(t *testing.T) {
			input := captureInput()
			org, actor, member, key := "org-29", "actor-17", "member-31", "key-59"
			switch field {
			case "ContactName":
				input.ContactName = "Another Contact"
			case "ContactEmail":
				input.ContactEmail = "Contact@example.com"
			case "Destination":
				input.Destination = "Norway\u0301"
			case "TravellerCount":
				input.TravellerCount = 3
			case "TravelStart":
				input.TravelStart = "2020-02-28"
			case "TravelEnd":
				input.TravelEnd = "2020-03-03"
			case "organization":
				org = "org-30"
			case "actor":
				actor = "actor-18"
			case "membership":
				member = "member-32"
			case "request key":
				key = "key-60"
			}
			got, err := creationFingerprint(vectorKey(), fingerprintAuthority(t, org, actor, member, created), key, input)
			if err != nil || got == base {
				t.Fatal("field not covered", err)
			}
		})
	}
	input := captureInput()
	input.ContactName = "Zoë"
	one, _ := creationFingerprint(vectorKey(), a, "key-59", input)
	input.ContactName = "Zoe\u0308"
	two, err := creationFingerprint(vectorKey(), a, "key-59", input)
	if err != nil || one == two {
		t.Fatal("Unicode normalization introduced", err)
	}
	otherKey := vectorKey()
	otherKey[0] ^= 1
	other, err := creationFingerprint(otherKey, a, "key-59", captureInput())
	if err != nil || other == base {
		t.Fatal("key not used", err)
	}
}

func TestCreationFingerprintExcludedValues(t *testing.T) {
	var previous [32]byte
	for i, id := range []string{"generated-1", "generated-2"} {
		a := fingerprintAuthority(t, "org-29", "actor-17", "member-31", created.Add(time.Duration(i)*time.Minute))
		e, err := enquiries.New(id, captureInput(), a)
		if err != nil {
			t.Fatal(err)
		}
		got, err := creationFingerprint(vectorKey(), a, "key-59", e.Input())
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && got != previous {
			t.Fatal("generated ID or action/audit timestamp entered fingerprint")
		}
		previous = got
	}
	// Event IDs and attestation request IDs have no input slot in this private
	// encoder. Actual command exclusion is also covered by simulated creations.
}

func TestCreationFingerprintFramingAndInvalidInput(t *testing.T) {
	a, err := frameCreationFields([]string{"a", "bc"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := frameCreationFields([]string{"ab", "c"})
	if err != nil || bytes.Equal(a, b) {
		t.Fatal("ambiguous field boundaries")
	}
	if hex.EncodeToString(a) != "0000000161000000026263" || hex.EncodeToString(b) != "0000000261620000000163" {
		t.Fatal("incorrect field lengths")
	}
	if got, err := frameCreationFields([]string{"valid", "\xff"}); !errors.Is(err, enquiries.ErrInvalidInput) || got != nil {
		t.Fatal("invalid UTF-8 returned partial bytes")
	}
	if got, err := fieldLength(math.MaxUint32); err != nil || got != [4]byte{255, 255, 255, 255} {
		t.Fatal("maximum length prefix")
	}
	if _, err := fieldLength(uint64(math.MaxUint32) + 1); !errors.Is(err, enquiries.ErrInvalidInput) {
		t.Fatal("length overflow accepted")
	}
	auth := fingerprintAuthority(t, "org-29", "actor-17", "member-31", created)
	for _, edit := range []func(*enquiries.Input){
		func(i *enquiries.Input) { i.ContactName = "\xff" }, func(i *enquiries.Input) { i.ContactName = " untrimmed" },
		func(i *enquiries.Input) { i.TravelEnd = "" }, func(i *enquiries.Input) { i.TravelStart = "2020-3-1" },
		func(i *enquiries.Input) { i.TravelStart = "2021-01-01" },
	} {
		input := captureInput()
		edit(&input)
		b, err := canonicalCreation(auth, "key-59", input)
		if !errors.Is(err, enquiries.ErrInvalidInput) || b != nil {
			t.Fatal("invalid input fingerprinted")
		}
	}
	for _, dates := range [][2]string{{"", ""}, {"0001-01-01", "9999-12-31"}} {
		input := captureInput()
		input.TravelStart, input.TravelEnd = dates[0], dates[1]
		if _, err := canonicalCreation(auth, "key-59", input); err != nil {
			t.Fatal("valid calendar range rejected", err)
		}
	}
}

func TestFirstCreatorConfigurationAndSecretCopy(t *testing.T) {
	identity := scriptedIdentity(script())
	id := func() (string, error) { return "id", nil }
	for _, size := range []int{0, 1, 31, 33, 64} {
		if c, err := NewFirstCreator(&pg.DB{}, identity, make([]byte, size), id); c != nil || err != ErrCreateConfiguration {
			t.Fatal("invalid key accepted")
		}
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	c, err := NewFirstCreator(&pg.DB{}, identity, key[:], id)
	if err != nil {
		t.Fatal(err)
	}
	original := key[0]
	key[0] ^= 1
	if c.secret[0] != original {
		t.Fatal("caller can mutate configured secret")
	}
	if _, err = NewFirstCreator(nil, identity, key[:], id); err != ErrCreateConfiguration {
		t.Fatal(err)
	}
	if _, err = NewFirstCreator(&pg.DB{}, nil, key[:], id); err != ErrCreateConfiguration {
		t.Fatal(err)
	}
	if _, err = NewFirstCreator(&pg.DB{}, identity, key[:], nil); err != ErrCreateConfiguration {
		t.Fatal(err)
	}
}
