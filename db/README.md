# Local PostgreSQL SQL foundation (Persistence Step 1)

Implemented for disposable, synthetic local tests only. The Go application still
uses immutable in-memory values; there is no enquiry database adapter or workflow
transaction coordinator. The bounded [Step 2A infrastructure](../internal/platform/postgres/README.md)
adds the driver and connection/transaction boundary only. The broader
[persistence design](../docs/ENQUIRY_PERSISTENCE_DESIGN.md) remains proposed beyond
this explicitly authorized SQL slice.

## Reproduce

Prerequisites: the existing Ubuntu/WSL PostgreSQL 18.6 installation, Bash, standard
Unix utilities (including flock), the existing Python 3 standard library with
Linux pidfd support, and the non-root cluster owner with peer-authenticated
bootstrap administration. No sudo, installation, container, migration framework,
or third-party module is needed. Python is used only for safe test-process
ownership and lifecycle verification, not application persistence.

From the repository in Ubuntu:

```bash
timeout 180 bash scripts/test-postgres.sh
```

From PowerShell in the Windows repository:

```powershell
wsl.exe -d Ubuntu --cd /mnt/c/Users/bkask/Documents/SoftterOs --exec /usr/bin/timeout 180 /usr/bin/bash scripts/test-postgres.sh
```

The harness expects the private cluster beneath
`$HOME/.local/share/softteros/pg18-dev`. It checks resolved data/socket paths,
ownership and mode 0700, installed version, empty TCP listen addresses, and
socket configuration before starting anything. Before database writes it checks
the live server's data path, user, version, Unix transport, authentication rules,
and system identifier against the control file at that data path. It never
changes the cluster configuration, authentication, or package services.

If stopped, it starts only this cluster and stops it in cleanup. If already
running, it leaves that instance running. Cooperating harnesses serialize the
whole run using a private `sql-test-lifecycle.lock` beneath the cluster root;
a contender fails after five seconds. Manual lifecycle commands must not run
concurrently. Startup is recorded before invoking pg_ctl. A per-run launcher
records PID, Linux start ticks, boot ID, user, data/executable paths and run
token before exec; cleanup seals its close-on-exec gate, preventing even a late
pg_ctl child from starting a server after a timeout. Cleanup pins the recorded
process with a pidfd, verifies its identity, and requests only that instance's
fast shutdown with a 30-second limit. It never stops by PID-file lookup alone.
An unverifiable identity or failed cleanup is reported as failure; interruption
exit codes (130/143) and prior failures are preserved. Repeated INT/TERM signals
are ignored during cleanup. A fresh UUID names four NOLOGIN test roles
(`stpg_<uuid>_owner/runtime/writer/lock`) and two databases
(`stpg_<uuid>_a/b`). Nothing is installed into an existing database. Bootstrap
role collisions fail atomically; database creation never overwrites a database.
Cleanup checks server identity, recorded database OIDs, owner, and run comments;
it drops only those databases and roles, without FORCE, CASCADE, or terminating
unrelated sessions. Failures refuse uncertain cleanup and report retained names.
Logs and exact created-object names are recorded under the printed
`$HOME/.cache/softteros-sql-test.*` directory, outside Git.

Every psql invocation uses `-X`, `ON_ERROR_STOP=1`, no password prompting, explicit
socket/user/database, and bounded connection, statement (10s), lock (500ms),
idle-transaction (10s), and transaction (20s) deadlines. The outer 180s timeout
requests termination; bounded cleanup can extend that deadline. These are test
budgets, not approved production policy.

### Lifecycle regressions and recovery

With the private cluster initially stopped, run directly in Ubuntu:

```bash
python3 scripts/test-postgres-lifecycle.py
```

The tests use real PostgreSQL plus test-only BASH_ENV wrappers and explicit file
barriers outside the repository. They cover INT/TERM during the original startup
window, repeated cleanup signals, a real pg_ctl one-second timeout with a delayed
launcher, an injected nonzero return after real successful startup, pre-launch
and PostgreSQL startup failures, refused ownership mismatch, competing harnesses,
normal runs, and failures/interruption with a pre-existing running instance.
Each case checks preservation of exact synthetic sentinel database/role OIDs and
the full original catalog inventory. `--original /absolute/saved/harness.sh`
also demonstrates the old leak using an external byte-identical harness copy;
it never overwrites the current implementation. Output identifies evidence and
exact run resources. The test suite restores its initially stopped state.
The additional private `sql-lifecycle-regression.lock` prevents concurrent
regression suites; both lock files remain outside Git and hold no credentials.

SIGKILL and machine crashes cannot guarantee shell cleanup. Keep the printed
LOGS directory and `objects.txt`; do not delete cluster directories or PID files,
kill processes by name, or drop resources by prefix. Before recovery, exclude
other harness/manual lifecycle work and inspect the server identity, recorded
`startup-process.json`, run UUID, and exact database OIDs/owners/comments. For a
run that started the server, this command seals late launches and attempts only
the recorded, verified process's shutdown (substitute that run's LOGS and UUID):

```bash
root="$HOME/.local/share/softteros/pg18-dev"
flock -n "$root/sql-test-lifecycle.lock" python3 scripts/postgres-lifecycle.py stop \
  /absolute/LOGS "$root/data" /usr/lib/postgresql/18/bin/postgres RUN_UUID
```

An identity mismatch, changed boot ID, or shutdown timeout requires inspection;
do not bypass the refusal. A run using an already-running server has no startup
ownership record and must leave that server alone. After verifying the cluster,
any retained test databases/roles require the same exact identity checks as the
harness before removal. Recovery is not a broad automatic cleanup procedure.

## Files and privileges

Step 2A adds a separate [Go connection/transaction boundary](../internal/platform/postgres/README.md). Run `python3 scripts/test-postgres-go.py` (and repeat with `--race`) for its synthetic integration suite. Its new test plumbing reuses the reviewed private-cluster lifecycle utilities and migrations without changing them; it creates a UUID-marked database/four roles, checks exact OIDs/owners/comments before cleanup, and preserves the initial server lifecycle. It requires the existing Go 1.27.3 toolchain and the approved pinned modules. It does not implement enquiry workflow persistence.

- `bootstrap.sql`: creates only the uniquely named test roles and their finite
  runtime/writer timeout defaults. Names and the run marker come from the harness.
- `migrations/001_tables.sql`: identifiers/finite instants, separate access and
  enquiry schemas, composite tenant keys/FKs, bounds, event shapes and receipt
  bindings. Global actor identity is separate from independent memberships.
- `migrations/002_integrity.sql`: immutable bindings/events/completed receipts,
  allowed row transitions, and deferred final history/receipt checks.
- `migrations/003_permissions.sql`: explicit grants, forced RLS, structural
  context checks and the narrow authority-fence lock helper.
- `tests/integration.sql`: synthetic fixtures and invoker-rights assertions.
  Temporary fixture helpers are test-only and disappear with the connection.
- `tests/commit_denials.sql`: separate connections prove missing events,
  missing receipts and pending receipts reach COMMIT, fail with 23514, and leave
  all business/event/receipt rows uncommitted.

Each migration is transactional and requires a fresh schema; there is no
`IF NOT EXISTS` repair/overwrite route. The owner role owns schemas/tables and
has an explicit migration RLS policy; it remains privileged. Runtime gets tenant
reads, enquiry/event/receipt inserts, and only transition/completion column
updates. It cannot administer authority, schemas, roles, ownership, RLS, or
history. These backend reads are not a general end-user read/audit capability.

The trusted writer can provision structural authority and update status,
validity, capabilities and revisions, but cannot mutate enquiries/events. This
does not define grant-administration eligibility or a policy engine. All actual
authority writers must participate in the documented fence protocol; table
permissions alone do not prove that protocol or external freshness.

The lock helper's distinct NOLOGIN owner owns no tables and has only schema
usage, fence SELECT/UPDATE needed for row locks, and context-check execution.
Its function validates exact actor/organization context, takes actor then
organization FOR SHARE locks, and returns revisions without mutation. It uses
fully qualified objects, `search_path=pg_catalog, pg_temp`, no dynamic SQL, and
PUBLIC execution is revoked in its creation transaction. Temporary schema CREATE
needed to transfer ownership is revoked in that same transaction.

Structural context/history functions also use fixed qualified queries and
PUBLIC execution denial. Runtime RLS requires well-formed existing actor,
organization and membership bindings; it does not infer active permission,
capability, human identity, expiry, or credential authenticity from those rows.
Historical attribution survives later membership revocation. A trusted backend
can choose another valid context: RLS does not protect against compromise of that
backend or privileged owners/administrators.

## Integrity and precision

Only New/unassigned/version 1, Under review/assigned/version 2, and
Qualified/same-assignee/version 3 are supported. Creation inserts New; updates
cannot replace original input/ownership/creator/time, skip or repeat a transition,
replace an existing assignee, or move time backward. Every committed version requires its
contiguous immutable event history and a completed, consistently bound receipt.
Event shapes retain the existing domain facts and add technical identifiers,
success outcome and positive authority revisions. Contacts/travel input never
enter events. No cascading history deletion is provided.

A receipt reserves one tenant/member/request key; its command, actor,
fingerprint and expected version cannot be rebound. Completion happens once,
and every completed field is immutable thereafter. Creation uses expected
version 0 to mean no pre-existing enquiry; transitions use 1 or 2. This is SQL
representation for this experiment, not an approved external command contract.
Synthetic 32-byte fingerprint fixtures are not production HMAC/key management.

Deferred constraints check final rows, including a receipt initially inserted
pending and completed later in the same transaction. Tests force pending checks
with `SET CONSTRAINTS ... IMMEDIATE`; no expiry engine is implemented in SQL.
The future coordinator must execute integrity checks before its final fresh
expiry check and preserve the original action instant.

Storage uses finite nonzero UTC-range timestamptz at PostgreSQL's microsecond
precision. SQL cannot detect nanoseconds already rounded during conversion:
the future adapter must reject unsupported source precision before binding.
Go snapshots remain nanosecond-preserving. SQL mirrors simple text/count bounds
and date completeness/order/range; complete Go text/email validation and validated
restore remain mandatory at the future adapter boundary.

## Evidence and limits

On PostgreSQL 18.6 Linux ARM64, the suite exercises two fresh databases per run,
complete creation/review/qualification transactions, two tenants with colliding
local enquiry IDs, multiple independent memberships, exact stored microseconds
and historical dates. It asserts intended SQLSTATEs (42501, 23503, 23505, 23514,
55000, 55P03), rollback without partial state/assignment/event/receipt, forced RLS,
context reset after commit/rollback, helper restrictions and a two-connection
writer lock conflict with a positive control after release. Bootstrap, database,
and migration collision tests assert 42710, 42P04 and 42P06 respectively.

Permission tests execute DML under restricted effective roles. Role escalation
tests also use a restricted session identity: SET ROLE alone retains the
bootstrap superuser session's ability to switch roles. This is controlled test
role switching, not proof of genuine runtime login or peer authentication.
A separate owner-only corrupt-history injection tests structural checks, not
runtime permissions. No authentication rule is weakened.

Still deferred: enquiry adapter, command orchestration, stored-version CAS
integration, fresh human/permission and expiry/revocation integration, durable
workflow success-return ordering,
duplicate/ambiguous-commit recovery, fingerprint keys, real-data controls and
production operations. SQL fixtures do not approve all broader design decisions
or establish authenticity of supplied authorization/audit facts.

Official PostgreSQL 18 references:
[row policies](https://www.postgresql.org/docs/18/sql-createpolicy.html),
[secure definer functions](https://www.postgresql.org/docs/18/sql-createfunction.html),
[session identity](https://www.postgresql.org/docs/18/sql-set-session-authorization.html),
[deferred checks](https://www.postgresql.org/docs/18/sql-set-constraints.html),
[locking](https://www.postgresql.org/docs/18/explicit-locking.html),
[date/time storage](https://www.postgresql.org/docs/18/datatype-datetime.html).

