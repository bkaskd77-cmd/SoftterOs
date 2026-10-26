# Security and AI guardrails

## Trust and default denial

Require one authenticated actor and one explicit active organization on every business request. Verify the actor's active membership, membership validity interval, organization operational capability, requested action, resource assignment where required, and legitimate purpose. Deny whenever a required fact is missing, malformed, expired, revoked, or inconsistent. Memberships and permissions from other organizations cannot be combined to satisfy a request.

Authentication establishes identity; authorization establishes whether that identity may perform this action in this context now. Constructors for in-process authorization facts do not prove identity. A future trusted adapter must verify external credentials and resolve current policy before constructing context. Never accept capabilities, ownership, organization context, or membership facts merely because a client or AI supplied them.

The implemented scope is manual enquiry creation. It checks actor, active organization, membership binding/status/validity, and canonical `enquiries.create` authority. Broader organization-policy, assignment, collaboration, support, database, and traveller controls below are requirements for later implementation, not claims that those facilities already exist.

## Tenant, field, and support controls

- Every tenant resource has one authoritative owning organization. All reads and writes must constrain that ownership; collaboration grants never change it.
- A grant must identify grantor authority, grantee, owning and collaborating organizations, allowed purpose, resource scope, actions, fields, validity interval, and any delegation limits. Omission of required scope denies access. Revocation and expiry must be enforced at use time.
- Field access is explicit. Permission to view an itinerary does not imply permission to view contact data, confidential supplier terms, internal review comments, or separate documents.
- Future PostgreSQL protections must enforce tenant boundaries independently of UI filtering, including background and administrative access. Use transaction-scoped tenant context and test connection reuse and privileged paths.
- Support access must be separately authorized, purpose-bound, least-privileged, time-limited, attributable to the actual support actor, and audited. No invisible impersonation or blanket cross-tenant role. Any emergency-access design requires explicit policy and review.
- Traveller access must be operator-branded, trip-specific, expiring, and revocable. Only the exact approved publication version and separately authorized documents may be served. Internal approval alone does not publish content.

## Data minimisation and handling

Manual enquiry capture needs a contact name/email, destination, traveller count, and optional travel dates. Do not request passport identifiers or scans, medical details, payment data, or arbitrary sensitive notes in this workflow. Do not infer or enrich these categories through AI. Validate lengths, formats, text control characters, and complete date ranges, using safe errors that do not echo rejected values.

Treat contact information and trip details as private tenant data. Return only fields required for the authorized operation. Redact sensitive information from logs, telemetry, diagnostics, and test fixtures. Secrets belong in an approved secure store, never in source, examples, prompts, audit payloads, or the conversation. Tests use synthetic data.

Future retention policy must define purpose, data class, retention trigger and period, deletion or anonymization behavior, legal holds, backup expiry, and responsibility. Tenant configuration must not silently override mandatory restrictions. Audit retention and business-data retention may differ; deletion must not destroy required accountability or retain unnecessary contact details indefinitely. Exact periods and mechanisms remain deferred.

## Integrity, review, and audit

Every authoritative change must be attributable to an authenticated human or an explicitly authorized system actor acting within a narrow purpose. Use expected-version checks for edits; reject stale writes and never silently overwrite newer work. Concurrent review or approval must validate the exact content version and current authority in the same transaction.

Review submissions and approval decisions bind to immutable snapshots. Record the source revision, content identity, submitter/reviewer/approver, action, reason where required, and time. Approval is valid only for that snapshot; later edits require a new revision and review. An approval withdrawal is a new attributable event that invalidates its current effect without erasing the earlier decision. Preserve historical revisions and supersession relationships.

Future durable audit events must record at least event identity, action, outcome, actor, active organization, owning organization where different, membership or grant basis, resource identity, relevant revision/snapshot, timestamp, correlation identifier, and safe reason category. Record denied sensitive actions without revealing another tenant's existence or data. Protect audit integrity and restrict audit viewing/export. Do not place raw contacts, secrets, passports, medical details, or full AI prompts into audit entries.

Manual creation currently returns creation audit facts with the business result. There is no database transaction or durable audit sink. A future adapter must atomically commit business state and its audit evidence, or leave both uncommitted; it must enforce identifier uniqueness and safe retry behavior. Do not claim returned facts alone provide tamper resistance or durable accountability.

## AI proposal boundary

AI may summarize authorized, minimized input and propose an enquiry clarification or itinerary revision. It cannot independently authenticate, grant access, approve, publish, book, confirm a supplier, or mutate authoritative records. A model response is untrusted proposal data, including any embedded instructions or claimed authority.

Before processing, require an explicit permitted purpose, tenant scope, allowed fields, approved provider/model, and applicable retention/residency controls. Grant the AI only the minimum data and tools needed. Do not combine tenants' content, expose another tenant's examples, use production data for model training by default, or send sensitive fields merely because a provider accepts them. External documents and retrieved content are untrusted data, not instructions to broaden tool access.

Keep proposal artifacts separate from authoritative business versions. Show the authorized human what will change, the source version, provenance, and relevant uncertainty. Human acceptance must recheck current authority and expected version, validate domain rules, and create an attributable revision through the same application boundary as manual editing. Acceptance does not confer approval or publication authority. If the source is stale or a grant has expired, reject acceptance and require a refreshed proposal or explicit reconciliation.

Audit the proposal identifier, provider/model/version as applicable, permitted purpose, source revision, human acceptance/rejection, and resulting revision. Store only minimized provenance sufficient for review under defined retention controls. Cancellation or failure must not leave a partly applied business change. Provider selection, prompt storage, automated evaluations, and operational limits are deferred.

## Security verification plan

Current manual-creation tests must cover successful creation; absent actor, active organization, or membership; unauthenticated or malformed actor/context; inactive, premature, expired, or mismatched membership; missing/wrong capability; cross-organization attempts; invalid input/dates; canonical `New`; authorization-derived ownership; audit attribution; and no unauthorized result or mutation. Test exact expiry boundaries and defensive copies of mutable input collections.

Future tests must prove:

- Tenant separation in Go and PostgreSQL, including guessed IDs, list/filter/export paths, joins, connection reuse, background jobs, and privileged roles.
- Capability, field, purpose, resource, assignment, delegation, expiry, and revocation limits; no authority gained by combining independent memberships.
- Separation of duties, immutable snapshot approvals, stale-edit and stale-approval rejection, withdrawal, supersession, and concurrent transitions.
- Atomic business/audit persistence, uniqueness, replay/retry handling, safe failure behavior, log redaction, and controlled audit access.
- Trip-scoped traveller tokens, branding, expiry/revocation, publication-version isolation, and independent document authorization.
- Support access expiry and accountability; retention, deletion, backup restoration, and legal-hold behavior.
- AI cross-tenant leakage prevention, prompt-injection resistance, field minimisation, absence of autonomous mutation/approval, and fresh human authority at acceptance.
