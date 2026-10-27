package enquiries

import (
	"errors"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ErrInvalidInput deliberately does not reveal or echo submitted field values.
var ErrInvalidInput = errors.New("invalid enquiry input")

// Input captures only the information needed to start a manual enquiry.
// There are no ownership, state, creator, passport, medical, or payment fields.
// Free-text notes and individual traveller records are deliberately absent.
// Both travel dates may be empty when timing is not yet known.
// Valid historical dates are accepted for delayed or historical capture.
type Input struct {
	ContactName    string
	ContactEmail   string
	Destination    string
	TravellerCount int
	TravelStart    string
	TravelEnd      string
}

// ValidateInput checks without changing input. Values must already be trimmed;
// invalid values are rejected rather than silently rewritten. at is the trusted
// creation instant, not a date supplied by the enquiry's caller.
func ValidateInput(input Input, at time.Time) error {
	if at.IsZero() || at.UTC().Year() < 1 || at.UTC().Year() > 9999 {
		return ErrInvalidInput
	}
	if !validText(input.ContactName, 120) || !validText(input.Destination, 200) {
		return ErrInvalidInput
	}
	if !validEmail(input.ContactEmail) || input.TravellerCount < 1 || input.TravellerCount > 99 {
		return ErrInvalidInput
	}
	if !validTravelDates(input.TravelStart, input.TravelEnd) {
		return ErrInvalidInput
	}
	return nil
}

func validText(value string, maxRunes int) bool {
	if value == "" || len(value) > maxRunes*utf8.UTFMax || !utf8.ValidString(value) || strings.TrimSpace(value) != value || utf8.RuneCountInString(value) > maxRunes {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

func validEmail(value string) bool {
	if len(value) > 254 || !validText(value, 254) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) {
			return false
		}
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Name == "" && address.Address == value
}
