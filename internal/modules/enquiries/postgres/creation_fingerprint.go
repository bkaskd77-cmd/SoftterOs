package postgres

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/bkasdk77-cmd/SoftterOs/internal/modules/enquiries"
	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
)

const creationFingerprintTag = "softteros.enquiry.create.fingerprint.v1"

// Version 1 is an immutable encoding contract, not a key version. These bytes
// contain private input: never log or retain the payload alongside the receipt.
func canonicalCreation(a authz.CreationAuthorization, key string, input enquiries.Input) ([]byte, error) {
	if !a.Valid() {
		return nil, authz.ErrUnauthorized
	}
	if !identifier(key) {
		return nil, ErrSelector
	}
	if err := enquiries.ValidateInput(input, a.AuthorizedAt()); err != nil {
		return nil, err
	}
	return frameCreationFields([]string{
		creationFingerprintTag, a.OrganizationID(), a.ActorID(), a.MembershipID(), key,
		"enquiry.created", "0", input.ContactName, input.ContactEmail, input.Destination,
		strconv.Itoa(input.TravellerCount), input.TravelStart, input.TravelEnd,
	})
}

func fieldLength(n uint64) ([4]byte, error) {
	var prefix [4]byte
	if n > math.MaxUint32 {
		return prefix, enquiries.ErrInvalidInput
	}
	binary.BigEndian.PutUint32(prefix[:], uint32(n))
	return prefix, nil
}

func frameCreationFields(fields []string) ([]byte, error) {
	var buf bytes.Buffer
	for _, value := range fields {
		if !utf8.ValidString(value) {
			return nil, enquiries.ErrInvalidInput
		}
		length, err := fieldLength(uint64(len(value)))
		if err != nil {
			return nil, err
		}
		buf.Write(length[:])
		buf.WriteString(value)
	}
	return buf.Bytes(), nil
}

func creationFingerprint(secret [32]byte, a authz.CreationAuthorization, key string, input enquiries.Input) ([32]byte, error) {
	var result [32]byte
	canonical, err := canonicalCreation(a, key, input)
	if err != nil {
		return result, err
	}
	mac := hmac.New(sha256.New, secret[:])
	mac.Write(canonical)
	copy(result[:], mac.Sum(nil))
	return result, nil
}
