# SoftterOs project blueprint

## Purpose and product boundary

SoftterOs is a private, multi-tenant B2B Travel and Tourism Operating System. It coordinates organizations' travel operations while preserving each organization's ownership, access boundaries, and accountability. An organization can hold multiple operational capabilities; it is not permanently classified into one exclusive business type.

The product excludes a public marketplace, payment processing, and a second travel-news portal. The first documented business workflow starts at manual enquiry capture and ends with an internally approved draft itinerary. Quotation, publication, reservations, supplier confirmation, and payments are outside that workflow. Passport and medical-data collection are also excluded.

## Approved architecture

| Concern | Direction | Present scope |
| --- | --- | --- |
| Core business rules and authorization | Go | Manual enquiry creation and bounded in-memory review/qualification transitions |
| Application structure | Modular monolith | Small packages with explicit boundaries; no speculative services |
| Primary persistence | PostgreSQL | SQL foundation, bounded connection/transaction infrastructure and [internal loading](../internal/modules/enquiries/postgres/README.md); workflow writes deferred |
| Workspaces and user interfaces | TypeScript and Next.js | Deferred; no frontend or HTTP interface |
| AI, machine learning, optimization | Bounded Python services only when justified | Deferred; proposal and human-acceptance rules are specified |

Use Go 1.27.3 and standard-library dependencies, with the narrow [Step 2A pgx infrastructure exception](../internal/platform/postgres/README.md). The required module is `github.com/bkasdk77-cmd/SoftterOs`. The repository was selected as `https://github.com/bkaskd77-cmd/SoftterOs.git` after the user corrected the owner spelling. These identifiers currently differ; the explicit module requirement is retained. Reconcile naming deliberately in a later authorized change before external integrations depend on it.

Business modules own their invariants. Platform authorization establishes scoped authority; it must not become a generic business-data repository. Future transport and persistence adapters call the application boundary and cannot bypass its checks. Database protections supplement Go enforcement rather than replacing it.

## Enquiry foundation

The foundation accepts minimal structured enquiry input: contact name, contact email, destination, traveller count, and an optional complete travel-date range. It has no caller-supplied owning-organization field, passport or medical fields, payment fields, or unrestricted notes field.

The creation operation requires a verified authenticated actor, one active organization, a valid active membership for that actor in that organization, and the exact `enquiries.create` capability. The canonical code constant is `authz.CapabilityCreateEnquiry`. Membership validity has explicit start and end instants; expiration is exclusive. Authorization is evaluated using injected time and the validated context supplies resource ownership and attribution.

The new enquiry starts in `New`. Private domain state and value-returning accessors prevent mutation through exported fields. Input validation and safe stable errors are part of the domain/application boundary. Identifier generation is injected and authorization precedes its invocation. The operation returns attributable creation/audit facts without persisting them. No in-place overwrite, storage, HTTP, or credential-verification mechanism is provided.

Authorized `New` → `Under review` → `Qualified` transitions are also implemented in memory, with atomic review self-assignment, exact-assignee qualification, expected-version checks, and detached audit facts. Detailed authorization and assignment policy is defined in the [canonical workflow](ENQUIRY_TO_DRAFT_ITINERARY_WORKFLOW.md).

The in-process authorization context is a trusted-facts interface, not an authentication protocol. A future adapter must authenticate credentials, resolve current membership and organization policy from trusted sources, and construct the context. Client JSON, AI output, stale caches, or claimed membership fields must never directly populate trusted facts.

## Ownership and collaboration

Every tenant-owned record has exactly one authoritative owning organization. Each business request selects one explicit active organization; a person's memberships in other organizations do not combine into ambient privileges. Collaboration grants and assignments restrict actions on particular resources without transferring their ownership.

Organization operational capabilities, membership authority, resource assignment, and purpose are distinct controls. A role bundle is a convenient set of candidate permissions, never a global bypass. Future actions must enforce all applicable controls in Go and PostgreSQL. The creation boundary's membership capability represents an already resolved entitlement supplied by the trusted authorization adapter; it does not implement the future organization-policy, collaboration, or assignment stores.

Traveller access is a separate, operator-branded, trip-specific, expiring, revocable route to approved versioned publications and separately authorized documents. It never exposes internal enquiries, working drafts, review comments, or unapproved revisions. Publication is deferred and is not implied by internal approval.

## Delivery discipline

Preserve recovered work before reconstruction when it exists. Keep local commits narrow and inspect staged content for secrets. Do not commit credentials, toolchains, caches, generated files, or machine-specific settings. A successful local commit is not deployment, backup outside the computer, or evidence of a durable business audit system.

Current security verification covers manual creation's authorization denials, ownership derivation, `New` state, input and date invariants, audit attribution, and resistance to mutation through returned values, plus the two enquiry transitions' authorization, assignment, state, and expected-version checks. Requirements for other workflow operations, collaboration, database, support, traveller, and AI behavior belong to the future test plans in the other foundation documents.

## Explicitly deferred decisions

- External identity/policy verification, authentication/session provider, request-context construction, refresh and revocation handling.
- Organization capability registry, role administration, assignment administration beyond review self-assignment, collaboration delegation, and policy storage.
- Application integration of the [SQL foundation](../db/README.md), transaction boundaries, stored-version concurrency, and atomic durable audit storage; production database approval remains separate.
- HTTP/API contracts, UI structure, transport validation, pagination, search, background processing, infrastructure, and deployment.
- Itinerary content model, review snapshot serialization/digests, publication and traveller access mechanisms.
- Retention periods, deletion schedules, residency, backup/restore, encryption and key management, and operational incident procedures.
- AI providers, models, permitted data classes, hosting, evaluation, cost controls, and human-acceptance UI.

Deferral does not relax the security requirements. Each later implementation must resolve the relevant decisions and prove its controls before exposing the functionality.

## Initial foundation verification

Recorded on 2026-10-27 from the completed 2026-10-26 validation run. The application code at preservation commit `3e959da58f23e1235762cc09bb75b1f21ead5d30` passed the following checks, in this order, using the checksum-verified official Go 1.27.3 Linux ARM64 toolchain on Ubuntu 26.04.1 LTS under WSL 2, with GCC 15.2.0 and cgo enabled:

| Command | Result |
| --- | --- |
| `go test -race -count=1 ./...` | Passed all three packages; no race reports |
| `go test -count=1 ./...` | Passed all three packages |
| `go vet ./...` | Passed |

Module inspection confirmed no third-party Go dependencies. Application code and tests were unchanged for this environment validation. The earlier Windows AMD64-emulation race run failed during ThreadSanitizer initialization with allocation error 87; the successful native Linux ARM64 run resolves that validation blocker without changing application behavior or disabling race detection. These results apply to the manual-creation foundation, not to the deferred functionality described above.
