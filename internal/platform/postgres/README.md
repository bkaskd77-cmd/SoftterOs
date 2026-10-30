# PostgreSQL infrastructure — Persistence Step 2A

This internal package provides native pgx connections and a transaction boundary.
It does not persist enquiry creation/review/qualification or establish identity,
human status, membership, capabilities, grants, authority freshness or expiry.
The [canonical persistence proposal](../../../docs/ENQUIRY_PERSISTENCE_DESIGN.md)
remains authoritative for future workflow orchestration. Domain and authorization
packages retain only standard-library dependencies.

## Use and trust boundary

Create explicit trusted `Config` using `DefaultConfig`, then `Open`; it returns
only after a bounded readiness check. Fields are not a client configuration API.
Never log Config, Password or connection strings. No DSN or libpq service file
is accepted. A nonempty ambient `PGSERVICE` fails closed before parser file
access; the password-file source is explicitly the platform null device, and
endpoint/credentials/runtime settings replace parser defaults. TCP requires
verified TLS; local tests keep Unix sockets, peer authentication and TCP disabled.

`WithTx(ctx, Scope, callback)` validates the exact ASCII identifier grammar before
acquiring a connection or invoking the callback. Scope must originate in a
trusted future adapter; valid strings are not authenticated or authorized facts.
One acquired connection runs `BEGIN ISOLATION LEVEL READ COMMITTED`, parameterized
transaction-local `set_config` for organization/actor, callback SQL and completion.
The callback receives only an Executor, with no commit/rollback/connection API.
Callback SQL is trusted: it must not issue transaction/session control, escape
the handle, retain rows, run concurrently, publish success or perform external
side effects. It must honor context cancellation. This is not an arbitrary SQL
endpoint, a generic CRUD layer or a defense against a compromised backend.

Both acquisition and release verify an idle connection with no tenant/actor
context. Residual settings, busy state, failed rollback, broken connections or
failed verification cause physical connection discard. Panic cleanup runs before
the original panic propagates; canceled requests use independent cleanup contexts.
`Close` cancels active operation contexts and bounds its wait; a callback ignoring
cancellation cannot be forcibly stopped by Go, so ErrCleanup can report an
incomplete close while final closure waits for that callback to return.

## Budgets and outcomes

Defaults: at most four connections (configurable 1–64), connection 5s, acquisition
2s, whole operation 20s, statement 10s, lock 500ms, idle transaction 10s,
connection lifetime 30m and idle lifetime 5m. All limits must be nonzero and finite;
lock < statement <= operation, idle transaction <= operation. PostgreSQL 18
connection settings enforce the statement/lock/idle/transaction limits before
blocking work. These are infrastructure defaults, not product authorization policy.

Each rollback, verification and discard/close phase gets an independent 3s
cleanup budget. Cleanup can extend a canceled request by up to 9s; Close bounds
its caller's wait at 3s by default. Shorter caller deadlines still apply to work.
Never use this boundary to wait for human approval or external network work.

Return nil means commit was acknowledged. Callback errors are preserved for the
trusted caller; future transport must sanitize arbitrary driver errors returned
by callbacks. Boundary-generated errors never include raw driver diagnostics.
`ErrCommitRejected` covers confirmed transaction rollback / recognized server
integrity or concurrency rejection. `ErrCommitUnknown` covers lost acknowledgement,
transport/cancellation during commit and unclassified responses. It is never
reported as rollback and is never automatically retried. Receipt lookup/recovery
is absent. Confirmed commit followed by connection discard still returns success;
the committed operation is not retried merely because a connection was unusable.

## Dependency review (2026-10-30)

Pinned native pgx/pgxpool **v5.11.0**, requiring Go 1.25+, compatible with the
unchanged Go 1.27.3 requirement. Necessary runtime transitives: pgpassfile v1.0.0,
pgservicefile v0.0.0-20240606120523-5a60cdf6a761, puddle/v2 v2.2.2,
x/text v0.41.0 and x/sync v0.22.0. No ORM, migration framework or second pool.
Upstream dependency-test checksums may also occur in go.sum; they are not new
application imports.

[pgx release notes](https://github.com/jackc/pgx/releases/tag/v5.11.0),
[Go compatibility](https://github.com/jackc/pgx/blob/v5.11.0/go.mod),
[pgx advisories](https://github.com/jackc/pgx/security/advisories).
The upstream x/text minimum v0.29.0 has
[GO-2026-5970](https://pkg.go.dev/vuln/GO-2026-5970) and
[GO-2026-6629](https://pkg.go.dev/vuln/GO-2026-6629); v0.41.0 fixes both and
requires x/sync v0.22.0. OSV's exact-version check found no matches for the six
selected runtime modules on the review date. This is a dated advisory check,
not a guarantee about future vulnerabilities or proof of production readiness.

The post-tidy graph contains 15 external modules. Its unused upstream tooling
requirements include x/mod v0.38.0, matching
[GO-2026-6179](https://pkg.go.dev/vuln/GO-2026-6179) and
[GO-2026-6180](https://pkg.go.dev/vuln/GO-2026-6180). Project/test import inspection
and `go mod why` confirm that x/mod and x/tools are not imported; no tooling is
executed from those modules. The unchanged Go 1.27.3 toolchain is outside these
advisories' affected cmd/go ranges. Reassess before adding upstream tooling.
`go mod verify` checks cached module integrity; it is not a vulnerability scan.

## Real PostgreSQL tests

From Ubuntu at the repository root:

```text
python3 scripts/test-postgres-go.py
python3 scripts/test-postgres-go.py --race
python3 scripts/test-postgres-go-runner.py
```

The runner uses the existing private cluster and reviewed migrations, with only
synthetic actor/membership anchors and a disposable test-only RLS probe table.
There is no enquiry storage adapter or business-command fixture implementation.
Tests install a restricted session/effective identity in an AfterConnect hook
that exists exclusively in `_test.go`; production code has no such hook or
administrative role switching. This proves SQL permission behavior, not genuine
runtime login/peer authentication. Administrative setup and termination of the
exact acquired test backend remain exclusively fixture plumbing.

Coverage includes readiness/invalid configuration, scope denial, omitted-filter
RLS isolation, one-connection A/B/no-context reuse after commit/rollback, durable
commit and deferred commit rejection, callback errors, cancellation during real
server work, panic cleanup, bounded exhaustion, session contamination, dead
connections, unknown commit outcomes, no automatic retry and shutdown cancellation.
Normal `go test ./...` skips database tests unless the runner supplies the explicit
integration environment. Future workflow persistence still requires current
authorization/fences/expiry, tenant-scoped business queries, stored-version
comparison, atomic business/audit writes, and deliberate commit recovery semantics.

The runner arms interruption cleanup before startup and includes initialization
and evidence writes in that protection. INT/TERM retains exit status 130/143;
repeated signals are ignored during cleanup. Creation intentions precede DDL.
Cleanup waits for this run's uniquely tagged SQL sessions to finish (30s wait
budget, with each query separately bounded), then checks the original catalog,
cluster/process identity, OIDs, role markers and database owner before deletion.
A database whose COMMENT was interrupted must have the verified new owner OID,
an absent pre-run identity and recorded creation intent. Names alone never
authorize cleanup; ambiguous ownership fails visibly without deletion. SQL calls
have 30s client deadlines and existing server timeouts; lifecycle settlement uses
the reviewed helper's 40s client bound. Cleanup phases can extend the work budget.

Runner regressions use real PostgreSQL and test-only wrappers to deliver INT/TERM
at explicit completed-command boundaries and inject evidence-write failures.
They require an initially stopped private cluster and cover both stopped and
already-running cases, repeat cleanup/signals, complete catalog preservation and
ambiguous-ownership refusal. SIGKILL or a machine crash cannot run shell/Python
cleanup reliably. Preserve the printed evidence directory and creation intent;
use the [reviewed recovery guidance](../../../db/README.md#lifecycle-regressions-and-recovery)
for the exact startup record, then inspect retained objects against intent,
original inventory, OIDs, markers and owner. Never recover by name prefix.

Actor-context tests use two actors in both organizations, independently check
bound settings and membership results, and reuse one backend after commit/rollback.
Controlled cancellation after a completed write requires context.Canceled without
ErrCleanup, rollback observed on another connection and reuse of the same healthy
backend. Separate broken-connection cases still require discard.

Local verification on 2026-10-30 passed normal/race tests, vet, module integrity,
all six PostgreSQL integration tests in normal/race modes, and the standalone
SQL suite. The exact disposable objects were removed, catalog/configuration
checks matched, and the initially stopped private cluster was stopped afterward.
These results cover this infrastructure slice, not future workflow persistence.
