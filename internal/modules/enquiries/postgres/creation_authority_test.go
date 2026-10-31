package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/bkasdk77-cmd/SoftterOs/internal/platform/authz"
	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type identityFunc func(context.Context, CreationIdentityRequest) (CreationAttestation, error)

func (f identityFunc) CurrentCreation(c context.Context, r CreationIdentityRequest) (CreationAttestation, error) {
	return f(c, r)
}

type creationRow func(...any) error

func (r creationRow) Scan(dest ...any) error { return r(dest...) }

type creationScript struct {
	pg.Executor
	order                                      []string
	active, revoked, capability                bool
	from, until, action, final                 pgtype.Timestamptz
	actor, org, member, memberActor, memberOrg string
	clocks                                     int
}

func script() *creationScript {
	return &creationScript{active: true, capability: true, actor: "actor-17", org: "org-29", member: "member-31", memberActor: "actor-17", memberOrg: "org-29",
		from: stamp(created.Add(-time.Hour)), until: stamp(created.Add(time.Hour)), action: stamp(created), final: stamp(created.Add(time.Microsecond))}
}
func (s *creationScript) QueryRow(_ context.Context, q string, args ...any) pgx.Row {
	return creationRow(func(dest ...any) error {
		switch q {
		case creationFenceSQL:
			if !reflect.DeepEqual(args, []any{"actor-17", "org-29"}) {
				panic("wrong fence binding")
			}
			s.order = append(s.order, "fences")
			*dest[0].(*int64), *dest[1].(*int64) = 7, 9
		case creationFactsSQL:
			if !reflect.DeepEqual(args, []any{"actor-17", "org-29", "member-31", "enquiries.create"}) {
				panic("wrong facts/capability binding")
			}
			s.order = append(s.order, "facts")
			*dest[0].(*string), *dest[1].(*string), *dest[2].(*string) = s.actor, s.org, s.member
			*dest[3].(*string), *dest[4].(*string) = s.memberActor, s.memberOrg
			*dest[5].(*bool), *dest[6].(*bool) = s.active, s.revoked
			*dest[7].(*pgtype.Timestamptz), *dest[8].(*pgtype.Timestamptz) = s.from, s.until
			*dest[9].(*bool) = s.capability
		case creationClockSQL:
			s.order = append(s.order, "clock")
			s.clocks++
			if s.clocks == 1 {
				*dest[0].(*pgtype.Timestamptz) = s.action
			} else {
				*dest[0].(*pgtype.Timestamptz) = s.final
			}
		default:
			panic("unexpected authority query")
		}
		return nil
	})
}

var creationRequest = CreationRequest{"actor-17", "org-29", "member-31", "request-43"}

func scriptedIdentity(s *creationScript) CreationIdentity {
	return identityFunc(func(_ context.Context, r CreationIdentityRequest) (CreationAttestation, error) {
		if r != (CreationIdentityRequest{"actor-17", "request-43"}) || !reflect.DeepEqual(s.order, []string{"fences"}) {
			panic("identity read before fences or wrong request")
		}
		s.order = append(s.order, "identity")
		return CreationAttestation{Actor: authz.Actor{ID: "actor-17", Authenticated: true}, RequestID: "request-43"}, nil
	})
}
func TestCreationAuthorityPolicyAndFreshTime(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*creationScript)
		want error
	}{
		{"valid", func(*creationScript) {}, nil},
		{"inclusive start", func(s *creationScript) { s.from = s.action }, nil},
		{"inactive", func(s *creationScript) { s.active = false }, authz.ErrUnauthorized},
		{"revoked", func(s *creationScript) { s.revoked = true }, authz.ErrUnauthorized},
		{"missing capability", func(s *creationScript) { s.capability = false }, authz.ErrUnauthorized},
		{"not yet valid", func(s *creationScript) { s.from = stamp(created.Add(time.Minute)) }, authz.ErrUnauthorized},
		{"exact expiry", func(s *creationScript) { s.until = s.action }, authz.ErrUnauthorized},
		{"expires before completion", func(s *creationScript) { s.until = s.final }, authz.ErrUnauthorized},
		{"wrong actor", func(s *creationScript) { s.actor = "other" }, authz.ErrUnauthorized},
		{"wrong organization", func(s *creationScript) { s.org = "other" }, authz.ErrUnauthorized},
		{"wrong member actor", func(s *creationScript) { s.memberActor = "other" }, authz.ErrUnauthorized},
		{"wrong member organization", func(s *creationScript) { s.memberOrg = "other" }, authz.ErrUnauthorized},
		{"wrong member", func(s *creationScript) { s.member = "other" }, authz.ErrUnauthorized},
		{"infinite validity", func(s *creationScript) { s.until.InfinityModifier = pgtype.Infinity }, ErrCreationUnavailable},
		{"unsupported precision", func(s *creationScript) { s.from.Time = s.from.Time.Add(time.Nanosecond) }, ErrCreationUnavailable},
		{"backward final clock", func(s *creationScript) { s.final = stamp(created.Add(-time.Microsecond)) }, ErrCreationUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := script()
			tc.edit(s)
			c := &CreationChecker{identity: scriptedIdentity(s)}
			err := c.authorize(context.Background(), s, creationRequest)
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("authority result: %v want %v", err, tc.want)
			}
			if tc.want == nil && !reflect.DeepEqual(s.order, []string{"fences", "identity", "facts", "clock", "clock"}) {
				t.Fatal("fresh-time/order checks omitted")
			}
		})
	}
}
func TestCreationIdentityFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		actor   authz.Actor
		request string
		failure error
		want    error
	}{
		{"missing", authz.Actor{}, "", nil, authz.ErrUnauthorized},
		{"disabled", authz.Actor{ID: "actor-17"}, "request-43", nil, authz.ErrUnauthorized},
		{"wrong actor", authz.Actor{ID: "actor-other", Authenticated: true}, "request-43", nil, authz.ErrUnauthorized},
		{"wrong request", authz.Actor{ID: "actor-17", Authenticated: true}, "other", nil, authz.ErrUnauthorized},
		{"unavailable", authz.Actor{}, "", errors.New("private provider details"), ErrCreationUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := script()
			c := &CreationChecker{identity: identityFunc(func(context.Context, CreationIdentityRequest) (CreationAttestation, error) {
				s.order = append(s.order, "identity")
				return CreationAttestation{Actor: tc.actor, RequestID: tc.request}, tc.failure
			})}
			err := c.authorize(context.Background(), s, creationRequest)
			if !errors.Is(err, tc.want) {
				t.Fatal("identity failure accepted", err)
			}
			if !reflect.DeepEqual(s.order, []string{"fences", "identity"}) {
				t.Fatal("authority facts read with invalid identity")
			}
		})
	}
}
func TestCreationCheckerConfigurationAndSelectors(t *testing.T) {
	if _, err := NewCreationChecker(nil, nil); err != ErrCreationConfiguration {
		t.Fatal(err)
	}
	var zero *CreationChecker
	if zero.Check(context.Background(), creationRequest) != ErrCreationConfiguration {
		t.Fatal("zero checker allowed")
	}
	c := &CreationChecker{db: &pg.DB{}, identity: identityFunc(nil)}
	for _, r := range []CreationRequest{{}, {"bad actor", "org-29", "member-31", "request-43"}, {"actor-17", "", "member-31", "request-43"}, {"actor-17", "org-29", "", "request-43"}, {"actor-17", "org-29", "member-31", ""}} {
		if c.Check(context.Background(), r) != authz.ErrUnauthorized {
			t.Fatal("malformed selectors reached pool")
		}
	}
}

type authorityFailure struct {
	pg.Executor
	err error
}

func (f authorityFailure) QueryRow(context.Context, string, ...any) pgx.Row {
	return creationRow(func(...any) error { return f.err })
}
func TestCreationAuthoritySafeFailures(t *testing.T) {
	c := &CreationChecker{}
	if c.authorize(context.Background(), authorityFailure{err: &pgconn.PgError{Code: "42501", Message: "private binding"}}, creationRequest) != authz.ErrUnauthorized {
		t.Fatal("helper denial leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := c.authorize(ctx, authorityFailure{err: errors.New("private connection details")}, creationRequest)
	if !errors.Is(err, ErrCreationUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}
