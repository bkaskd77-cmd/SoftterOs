# SoftterOs repository instructions

## Product and architecture

SoftterOs is a private, multi-tenant B2B Travel and Tourism Operating System. Read the four documents in `docs/` before changing business rules or authorization. Preserve valid recovered material and existing Git history; change it only for a concrete requirement or defect.

The approved direction is a Go modular monolith for core business rules and authorization, PostgreSQL for future persistence, TypeScript and Next.js for future workspaces, and Python only for bounded AI, machine-learning, or optimization services. There is no public marketplace, payment processing, or second travel-news portal.

## Current implementation boundary

The bounded in-memory Go foundation implements manual enquiry creation and authorized `New` → `Under review` → `Qualified` transitions, with atomic review self-assignment, exact-assignee qualification, expected-version checks, and detached audit facts. The [canonical workflow](docs/ENQUIRY_TO_DRAFT_ITINERARY_WORKFLOW.md) defines the detailed policy; other workflow operations remain specifications.

External identity/policy verification, durable persistence, stored-version concurrency, atomic durable audit storage, API, UI, and infrastructure remain unimplemented/deferred. Do not add HTTP handlers, database adapters, SQL, migrations, frontend code, authentication vendors, queues, deployment configuration, or unrelated modules without a later task authorizing them.

Persistence Step 1 adds only the authorized [SQL foundation and disposable local tests](db/README.md). It does not integrate application persistence or authorize a Go adapter, dependencies, real data, or deployment. Keep later database work explicitly bounded.

Step 2A authorizes only the [PostgreSQL connection/transaction infrastructure](internal/platform/postgres/README.md), native pgx v5/pgxpool and necessary pinned transitives, plus synthetic integration tests. Workflow persistence, external authentication and deployment remain deferred. The dependency exception is confined to infrastructure; domain and authorization stay standard-library-only.

The separately authorized [internal enquiry loader](internal/modules/enquiries/postgres/README.md) reconstructs validated historical values within that transaction boundary. It grants no business read access and implements no workflow writes or current authorization orchestration.

Use Go 1.27.3 and only the Go standard library outside the explicit Step 2A infrastructure exception. Keep the explicitly required module path `github.com/bkasdk77-cmd/SoftterOs`. The Git remote is the user-corrected `https://github.com/bkaskd77-cmd/SoftterOs.git`; the spelling difference is intentional preservation of the task's module requirement, not permission to fetch a second repository.

## Security invariants

- Every tenant resource has one authoritative owning organization. Collaboration and assignments never transfer ownership.
- Require authenticated actor, explicit active organization, valid active membership bound to that actor and organization, and the exact required capability. Missing or malformed context denies access.
- Use the canonical `enquiries.create` capability through `authz.CapabilityCreateEnquiry`; do not create aliases or wildcard bypasses.
- Construct authorization facts only from a trusted, verified adapter. In-process context constructors do not authenticate browsers or validate external credentials.
- Derive enquiry ownership from validated authorization context; never from enquiry input. New enquiries begin in `New`.
- Keep domain state private. Return values or defensive copies, use stable safe errors, and return no partial business result on failure.
- Inject time and identifier generation where needed for deterministic behavior. Check authorization before invoking side-effectful collaborators.
- Collect only the fields needed for manual capture and response. Passport, medical, payment, and arbitrary sensitive free-text collection are outside this boundary.
- AI may propose changes but cannot authorize, approve, publish, or independently mutate authoritative records.
- Future persistence must enforce tenant isolation and atomic business/audit writes in addition to Go checks. Returning audit facts alone is not a durable audit trail.

## Working and validation

Read relevant existing code and tests in batches before modifying them. Preserve unrelated local changes and stage only task-relevant files. Never log credentials or `.env` values. Keep toolchains, caches, generated files, and machine-specific settings out of commits.

For Go changes, format with `gofmt`, confirm dependencies are limited to the approved infrastructure exception, and run:

```text
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
git diff --check
```

Test denial cases, tenant boundaries, immutable results, date/input invariants, and attributable audit facts rather than targeting a test count. Inspect staged content for secrets and unrelated changes. Report checks actually run, exact failures, and environment blockers; never describe skipped or failing checks as passing.

Do not use destructive Git commands, rewrite history, push, deploy, create cloud resources, or change external accounts unless the current task authorizes that action. Local commits must preserve recoverable work and accurately describe their validation status.
