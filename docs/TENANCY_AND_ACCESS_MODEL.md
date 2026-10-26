# Tenancy and access model

## Core concepts

| Concept | Meaning |
| --- | --- |
| Organization | Tenant and authoritative owner of its resources; may have multiple operational capabilities |
| Actor | Authenticated person or explicitly permitted system identity; identity alone grants no business access |
| Membership | Independent binding of an actor to one organization, with status, validity, and scoped authority |
| Active organization | One explicit organization selected for the current business request |
| Operational capability | Business function an organization is permitted to perform |
| Action capability | Permission for a particular action, such as canonical `enquiries.create` |
| Assignment | A scoped responsibility/access relationship for a resource, subject to role, purpose, fields, actions, and time |
| Collaboration grant | Owner-authorized access for another organization or actor to specified resources without transfer of ownership |
| Publication | Approved, versioned content explicitly released through a separate publishing workflow |

An actor may belong to several organizations. Those memberships remain independent. Choosing one active organization does not import another organization's permissions, assignments, grants, or data. There is no implicit global business context and no “all my tenants” mutation.

## Authorization decision

For every action, the Go boundary must establish:

1. The actor is authenticated and the active organization is explicit and valid.
2. The actor's membership belongs to that organization, is active, and is within its validity interval.
3. The organization has the required operational capability and the membership has the action capability.
4. The resource belongs to the active organization, or a current owner-issued collaboration grant explicitly permits the request.
5. Required assignment, purpose, resource/action scope, field restrictions, delegation limits, and duration all permit the action.
6. Any state, version, approval, or separation-of-duties condition also permits the action.

All applicable conditions must hold. A role label, matching email domain, possession of an identifier, or a collaborator's membership is insufficient. Missing required context denies. Check authority again at mutation/acceptance time, not just when a screen opens. Revocation must invalidate future use; caching must not extend authority beyond its permitted validity.

The manual-creation implementation validates trusted actor, organization, membership, and action-capability facts. The capability is `enquiries.create`, represented once by `authz.CapabilityCreateEnquiry`. Membership start/end bounds are explicit, with an inclusive start and exclusive end. The trusted adapter is responsible for resolving any upstream organization policy before supplying that effective capability. No policy database or external credential verifier exists yet.

Creation has no pre-existing enquiry to assign. Its permission is scoped to creation in the validated active organization; it does not imply future read, edit, assignment, review, or approval rights. The created resource's owning organization comes exclusively from authorization context, never from enquiry input. Assignment administration and subsequent resource operations are deferred.

## Role bundles and duties

Roles are organization-scoped convenience bundles whose effective permissions are intersected with capability, assignment, purpose, resource, field, and time constraints. A person may hold multiple bundles; conflicting duties are enforced per decision regardless of their role names.

| Illustrative bundle | Intended responsibility | Required limit |
| --- | --- | --- |
| Enquiry intake | Capture and triage assigned enquiries | No implied itinerary approval, publication, or cross-tenant access |
| Enquiry coordinator | Qualify enquiries and manage authorized workflow/assignments | Cannot grant authority beyond their own delegated scope |
| Itinerary drafter | Create attributable working revisions for assigned work | Cannot approve a snapshot they authored or materially changed |
| Internal reviewer/approver | Review and decide on exact submitted snapshots | Must be distinct from the author(s) of the approved content and currently authorized |
| Organization access administrator | Manage scoped membership and role policy | Administration is not automatic access to business content or approval authority |
| Auditor | Inspect authorized audit evidence | Read-only, minimized scope; no business mutation |
| Support | Resolve a specifically authorized issue | Separate, expiring support grant; no invisible impersonation |

Approval uses a four-eyes rule. A drafter cannot approve their own content by switching role bundles or organizations. A reviewer who changes content becomes an author of the resulting revision and another eligible approver must decide it. No self-approval exception is assumed; any future exceptional policy must be explicit, attributable, and separately authorized.

## Collaboration and assignments

The owning organization remains authoritative for a shared resource. A collaboration grant must identify grantor, grantee, owning and active/collaborating organizations, purpose, resources, actions, permitted fields, validity interval, revocation state, and delegation policy. A grant may reduce access further than a role or assignment. It never grants capabilities the issuer lacks and never transfers ownership.

Assignments identify the responsible actor or organization and the exact responsibility. Assignment alone is not a capability grant. Require both current membership/grant authority and the required assignment for resource work. List, search, export, document download, and bulk operations must apply the same restrictions as single-resource access.

Delegation is denied unless explicitly allowed. A delegated grant must be no broader or longer-lived than its parent and must remain linked to it; revocation or expiry of a parent invalidates derived authority. An unspecified purpose or resource set is not a wildcard. Broad organizational grants, if later needed, require an explicit scope representation and policy rather than interpreting empty fields as “all”.

Field permissions apply to both reads and writes. Never expose internal notes or contacts merely because a collaborator can contribute itinerary content. The future schema and authorization model must distinguish resource ownership, originating organization, collaborating organization, and active organization where they differ.

## Traveller access

Traveller access is operator-branded, trip-specific, expiring, and revocable. It is a separately controlled access channel, not an internal organization membership or collaboration grant. It can access only the exact approved, versioned publication authorized for that trip plus documents with independent permission checks.

Do not expose internal enquiries, working drafts, previous unpublished versions, internal comments, supplier-confidential fields, or other travellers' records. Internal approval does not publish. Token/session design, identity verification, document delivery, publication withdrawal, and branding enforcement remain deferred.

## Enforcement and accountability

Enforce tenant and access rules in Go and eventually in PostgreSQL. Never rely on frontend hiding, client-side filtering, inferred tenant IDs, or a single unrestricted database user for business authorization. Every persistence path must constrain authoritative ownership, including joins and background work. The exact row-level-security and transaction-context design is deferred and must account for connection pooling and privileged operations.

Record attributable membership/grant decisions and business changes with safe audit facts. Support, sensitive-field access, exports, retention actions, and AI processing need explicit purposes and controls. Do not log raw secrets or unnecessary personal data. Audit readers also require scoped authorization.

Future tests must cover independent memberships, active-organization switching, cross-tenant identifiers, missing organization capability, missing assignment/purpose, restrictive fields, nested delegation, grant revocation/expiry, parent-child validity, support boundaries, role conflicts, and database enforcement. Manual creation tests cover only the currently implemented subset; no unimplemented access path should be represented as secured.
