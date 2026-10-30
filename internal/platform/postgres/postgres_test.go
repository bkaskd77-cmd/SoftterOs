package postgres

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestConfiguration(t *testing.T) {
	base := DefaultConfig("/private/socket", 5432, "synthetic", "synthetic")
	for name, mutate := range map[string]func(*Config){
		"host": func(c *Config) { c.Host = "" }, "database": func(c *Config) { c.Database = "" },
		"user": func(c *Config) { c.User = "" }, "port": func(c *Config) { c.Port = 0 },
		"pool": func(c *Config) { c.MaxConns = 0 }, "huge pool": func(c *Config) { c.MaxConns = 65 },
		"timeout": func(c *Config) { c.AcquireTimeout = 0 }, "unbounded lifetime": func(c *Config) { c.MaxConnLifetime = 0 },
		"lock ordering":   func(c *Config) { c.LockTimeout = c.StatementTimeout },
		"TCP without TLS": func(c *Config) { c.Host = "localhost" },
		"unverified TLS":  func(c *Config) { c.Host = "localhost"; c.TLS = &tls.Config{InsecureSkipVerify: true} },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			if _, err := poolConfig(c); err != ErrConfig {
				t.Fatalf("error %v", err)
			}
		})
	}
	// Ambient libpq settings must not become runtime scope, timeouts or endpoints.
	t.Setenv("PGOPTIONS", "-c softteros.organization_id=untrusted")
	t.Setenv("PGHOST", "bad-host")
	t.Setenv("PGSERVICE", "must-not-read")
	t.Setenv("PGPASSFILE", "must-not-read")
	if _, err := poolConfig(base); err != ErrConfig {
		t.Fatal("ambient service must be refused before file access")
	}
	t.Setenv("PGSERVICE", "")
	pc, err := poolConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	if pc.ConnConfig.Host != base.Host || pc.ConnConfig.RuntimeParams["softteros.organization_id"] != "" || pc.ConnConfig.RuntimeParams["options"] != "" {
		t.Fatal("ambient configuration inherited")
	}
	if pc.ConnConfig.TLSConfig != nil || len(pc.ConnConfig.Fallbacks) != 0 || pc.MaxConns != 4 {
		t.Fatal("unsafe defaults")
	}
	if millis(time.Minute) != "60000" {
		t.Fatal("timeout encoding")
	}
	if strings.Contains(ErrConfig.Error(), "must-not-read") {
		t.Fatal("configuration disclosure")
	}
}

func TestInvalidScopeBeforePoolOrCallback(t *testing.T) {
	d := &DB{} // Any attempt to acquire would panic.
	for _, s := range []Scope{{}, {"org-1", ""}, {"", "actor-1"}, {"../org", "actor"}, {"org", "bad actor"}, {strings.Repeat("a", 129), "actor"}, {"é", "actor"}} {
		called := false
		err := d.WithTx(context.Background(), s, func(context.Context, Executor) error { called = true; return nil })
		if err != ErrScope || called {
			t.Fatalf("invalid scope reached callback: %v", err)
		}
	}
	if !validID("org_2-A") || !validID("2") {
		t.Fatal("valid ID denied")
	}
}

func TestCommitClassification(t *testing.T) {
	for _, e := range []error{context.Canceled, context.DeadlineExceeded, errors.New("lost acknowledgement"), &pgconn.PgError{Code: "40003"}, &pgconn.PgError{Code: "57P01", Severity: "FATAL"}} {
		if commitError(e) != ErrCommitUnknown {
			t.Fatal("uncertain outcome reported as rollback")
		}
	}
	for _, e := range []error{pgx.ErrTxCommitRollback, &pgconn.PgError{Code: "23514", Severity: "ERROR"}, &pgconn.PgError{Code: "40001", Severity: "ERROR"}} {
		if commitError(e) != ErrCommitRejected {
			t.Fatal("server rejection not classified")
		}
	}
}
