# Internal enquiry loading

This package implements only database-to-domain loading for trusted internal
callers. It has no application operation, public read capability, workflow write,
external authentication, receipt recovery, or transport integration.

Call `Load(ctx, tx, organizationID, enquiryID)` **inside** the existing
[`postgres.DB.WithTx`](../../../platform/postgres/README.md) callback, using that
callback's context and Executor. The transaction owner retains completion and
must discard the candidate if the surrounding transaction fails. Never pass a
pool, unscoped connection, or client-supplied authorization context. Current
business authorization must precede contact-data access when a later coordinator
integrates this component. Scoped settings and RLS are not authorization.

One parameterized SELECT loads the enquiry, ordered events, completed receipt
bindings, and historical membership/assignee/grant references in a single MVCC
snapshot. Explicit organization predicates and tenant-qualified references
supplement the unchanged forced RLS policies. There are no locks or writes, so
the result is a consistent historical read, not protection against a later write.
Future commands still need authority fences, fresh authorization/expiry, stored
version checks, and atomic state/assignment/event/receipt writes.

Mapping rejects missing or inconsistent history, invalid references, unexpected
versions/shapes, and invalid typed representations, then calls the existing
domain-owned `enquiries.Restore`. It does not replay creation/transitions, repair
records, or manufacture authorization. `Loaded.Transitions` contains detached
stored historical audit facts; returning them does not emit success events or
authorize audit browsing. Ordinary creator/assignee/grant revocation does not
erase historical attribution. SQL reference and receipt constraints remain
unchanged; reconstruction does not establish provenance or historical permission.

Instants must be finite, nonzero, within UTC years 1–9999, and exactly
microsecond-representable. Decoding rejects unsupported precision without
rounding or truncation. UTC representation preserves the instant; domain snapshot
nanosecond behavior is unchanged. Calendar dates are mapped by year/month/day,
not timezone conversion; NULL pairs remain absent and valid historical dates
remain accepted. This read boundary cannot detect precision already lost before
storage; any future writer must reject unsupported precision before binding.

Missing and inaccessible rows both return `ErrNotFound` and zero results.
Malformed selectors return `ErrSelector` before SQL; corrupt representations
return `ErrStored`; query failures return `ErrStorage`. No error contains raw
driver diagnostics, contact values, identifiers, or SQL. There is no retry.

Unit tests use decoded records to test corruption without weakening database
constraints. The existing disposable harness runs the real loader tests:

```text
python3 scripts/test-postgres-go.py
python3 scripts/test-postgres-go.py --race
```

Administrative synthetic fixtures and transaction-local restricted role switching
exist exclusively in tests. Assertions check effective role attributes; these
tests do not prove genuine runtime-login authentication. They cover all three
states, independent creator/reviewer identities, offboarded historical bindings,
tenant-local ID collisions, inaccessible rows, absent context, exact timestamp
and calendar boundaries, and a committed transition between SELECT execution
and result consumption. The latter requires one query and verifies both the old
consistent result and a subsequent read of the new committed version.

The broader [persistence design](../../../../docs/ENQUIRY_PERSISTENCE_DESIGN.md)
remains proposed outside separately approved bounded work.

Technical references: PostgreSQL 18 [READ COMMITTED snapshots](https://www.postgresql.org/docs/18/transaction-iso.html#XACT-READ-COMMITTED)
and [date/time representation](https://www.postgresql.org/docs/18/datatype-datetime.html).
