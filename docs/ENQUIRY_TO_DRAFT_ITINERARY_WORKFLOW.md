# Enquiry to internally approved draft itinerary

## Boundary and implementation status

This workflow starts with manual enquiry capture and ends with an internally approved draft itinerary. It excludes quotation, publication, reservations, supplier confirmation, and payment processing. Passport and medical-data collection are outside the workflow.

Manual enquiry creation and the in-memory `New` → `Under review` → `Qualified` transitions, including review self-assignment, are implemented. Other transitions, drafting, reassignment, revisions and approval below remain specifications for future bounded work. There is no HTTP interface, Go database adapter, integrated durable audit log, frontend, AI integration, or traveller delivery mechanism.

**Persistence boundary:** [Enquiry persistence design](ENQUIRY_PERSISTENCE_DESIGN.md) describes storage for these three operations. Its SQL-only local test slice is implemented as documented there; the broader design remains proposed and does not change this workflow's approved policies or authorize further database work.

## Capture and ownership

An authenticated actor selects one explicit active organization. Creation requires a current active membership for that actor and organization and canonical `enquiries.create` authority (`authz.CapabilityCreateEnquiry`). The owning organization is derived exclusively from validated authorization context. Client enquiry fields cannot select or replace it.

Capture only contact name and email, destination, traveller count, and an optional complete travel-date range. Reject invalid input with stable safe errors. A provided date range must contain valid calendar dates in `YYYY-MM-DD` format, with the start on or before the end; partially supplied or malformed ranges are invalid. Creation captures supplied valid dates unchanged, including past dates for delayed or historical enquiries. Travel dates are not compared with the authorization or creation date. Whether those dates remain operationally actionable belongs to later review or qualification. Do not collect passport, medical, payment, or unnecessary sensitive information. The current structured input has no arbitrary notes field.

A successful capture produces a new immutable-domain enquiry in `New` with an identifier, creator, organization, membership basis, and creation time. Return attributable creation audit facts with it. Identifier generation and time are injected; authorization precedes identifier generation. The current operation does not save a record, update an existing record, or durably write an audit event.

## Enquiry lifecycle

| State | Meaning |
| --- | --- |
| New | Captured and awaiting triage; canonical initial state |
| Under review | An authorized assigned person is checking completeness, legitimacy, and suitability |
| Qualified | Sufficient, permitted information exists to begin planning and an authorized person has qualified it |
| Drafting | An assigned drafter is preparing or revising an itinerary |
| Draft ready | The current intended draft version is internally approved and its approval is still effective |
| Not proceeding | An authorized decision stops further work, with a minimized reason |
| Duplicate | An authorized decision identifies another enquiry; any link remains within permitted tenant/resource scope |
| Spam | An authorized decision identifies unwanted or malicious intake |
| Archived | Closed to ordinary workflow changes under the retention/access policy |

The normal progression is `New` → `Under review` → `Qualified` → `Drafting` → `Draft ready`. Each transition requires current capability, assignment where relevant, purpose, ownership/grant scope, and expected version. Qualification can be returned to `Under review` with an attributable reason if material information becomes insufficient. Draft work with material missing information may also return to `Under review`; existing drafts remain historical evidence.

Authorized triage or coordination may move an enquiry that has not reached `Draft ready` to `Not proceeding`, `Duplicate`, or `Spam`. These are explicit decisions, not automatic AI classifications. Duplicate handling must not merge or delete records silently or reveal an inaccessible record. A `Draft ready` enquiry must first have its approval effect withdrawn and associated drafts handled explicitly before a closing outcome is applied.

Closing outcomes may be archived; `Draft ready` may be archived after its associated itinerary is archived through an authorized action. Archiving records an event and restricts access; it is not deletion and must respect retention controls. Reopening, automatic transitions, and restoration of archived enquiries are deferred and denied until specified. Approval withdrawal moves `Draft ready` back to `Drafting` with a new working revision; it cannot remain ready on the strength of a withdrawn approval.

### Review and qualification authorization

The following approved rules are implemented as immutable in-memory results. State, assignment and audit facts are returned together; future persistence must atomically check stored versions and commit that outcome with fresh authorization. There is no shared authoritative store or durable audit sink yet.

| Operation | Required canonical capability | Transition | Assignment rule |
| --- | --- | --- | --- |
| Start review | `enquiries.review` | `New` → `Under review` | The enquiry must be unassigned. Atomically assign it to the acting membership while changing state. |
| Qualify | `enquiries.qualify` | `Under review` → `Qualified` | The acting membership must be the enquiry's current assignee. Preserve that assignment. |

These are independent capabilities. Possessing `enquiries.review` does not grant qualification, and possessing `enquiries.qualify` does not grant review. `enquiries.create` grants neither transition. Administrative status, role labels, or assignment alone grant neither capability; there is no implicit administrative bypass.

Both operations require a verified authenticated human actor, an explicit active organization, an active membership bound to that actor and organization, and a current authorization grant bound to that actor and membership and scoped to the enquiry and required action. The actor must act through that membership in the same authoritative organization as the active organization, grant, and enquiry owner. Resolve those facts from trusted authorization sources and the authoritative enquiry, never from caller-controlled enquiry fields or AI output. Memberships in other organizations and collaboration grants cannot bypass this same-organization requirement for these two transitions. Existing purpose, resource, action, and field restrictions continue to apply.

Check membership and grant status and validity at the authoritative action instant. Membership validity retains its inclusive start and exclusive end. Missing, malformed, mismatched, inactive, revoked, not-yet-valid, or expired membership/grant facts deny access. Authorization and audit timestamps come from trusted server time and remain separate from supplied travel dates.

Deny the operation when any required condition fails, including:

- A missing or wrong capability, including possession of only the other transition capability.
- Direct `New` → `Qualified`, an invalid current state, a skipped transition, or a repeated transition.
- Starting review on an already assigned enquiry; never overwrite or transfer its assignment.
- Qualification with no current assignee or by a different membership. Matching the assignee's actor alone is insufficient when the membership differs.
- Cross-organization actor/membership, active-organization, grant, or enquiry ownership mismatches.
- Reassignment, supervisor override, delegation, or bulk transitions; all remain deferred and unavailable by default. AI cannot start review, assign an enquiry, qualify it, or approve a transition.

Validate authorization, current state, assignment, and expected version before mutation. Starting review must commit the assignment and state change together; qualification must preserve the assignee. Each successful operation requires attributable audit information recording the authoritative organization and active organization, enquiry identifier, previous and new states, actor, acting membership, authorization grant basis, exact capability, previous and resulting assignee, and authoritative timestamp. State, assignment, and success audit evidence form one atomic outcome. A denied or failed operation leaves the enquiry, assignment, and existing audit facts unchanged and produces no success event. Safe denial audit records are distinct from success events and must not expose sensitive values.

The implementation uses a minimal in-memory expected-version counter for these two transitions. Persistent version comparison, transaction representation and durable audit implementation remain deferred; future persistence must check the stored version and current authority atomically with state and audit writes. Returning in-memory audit facts alone is not a durable audit record.

## Itinerary lifecycle and versions

| State | Meaning |
| --- | --- |
| Working draft | Editable only by an authorized assigned drafter through attributable revisions |
| In internal review | An immutable submitted snapshot awaits an eligible review decision |
| Changes requested | Review identified required changes against that exact snapshot |
| Internally approved | An eligible approver accepted the exact submitted snapshot for internal use |
| Archived | Removed from ordinary active workflow while retained under policy |

`Superseded` identifies historical itinerary versions; it is not an extra editable lifecycle state. Preserve the relationship between a version and its successor. Supersession does not erase content, authorship, review decisions, or prior approvals, and a historical approval never authorizes a different version.

The normal progression is `Working draft` → `In internal review` → `Internally approved`. A reviewer may instead select `Changes requested` with attributable comments. Addressing those comments creates a new `Working draft` revision and a new submission; it must not mutate the reviewed snapshot. An approved version cannot be edited in place. Further changes create a new working revision and require a fresh review and approval before `Draft ready` can refer to it.

Only current authorized roles can archive a version. Archiving must not silently preserve an effective readiness or approval claim inconsistent with the active version. The future implementation must make version selection and approval effect explicit; it cannot infer current approval from the existence of any historical approval event.

## Assignments, roles, and separation of duties

Organization operational capability, membership action authority, and resource assignment are independent. Creation authority does not automatically authorize later reading, editing, qualification, assignment, or approval. A coordinator may assign work only within their current delegated scope. Collaboration grants can restrict resources, actions, fields, purpose, delegation, and duration, and never transfer ownership.

The intake, coordinator, drafter, and reviewer/approver bundles described in `TENANCY_AND_ACCESS_MODEL.md` support this workflow. Enforce a four-eyes approval rule: an author of the content being approved cannot approve it. Switching roles does not bypass this restriction. If a reviewer edits the content, another eligible reviewer must approve the resulting snapshot. No implicit self-approval or organization-admin override is allowed.

## Revision and decision integrity

Every proposed edit carries the expected current revision. Reject stale edits with a safe conflict result and require an explicit refresh/reconciliation; never silently apply last-write-wins. Record each accepted revision's author, time, parent revision, change purpose, and relevant source/proposal references. Keep sensitive values out of generic audit summaries.

Submitting for review creates an immutable snapshot identified by revision and stable content identity. Review comments, requested changes, and approval bind to that exact snapshot. At approval time, atomically check current actor authority, assignment, separation of duties, review status, source version, and any grant expiry or revocation. A stale submission cannot be approved as though it were current.

Approval records must include approver, active/owning organization context, membership or grant basis, snapshot identity, time, and decision. Withdrawal requires its own currently authorized action, reason, actor, and time. Preserve the original approval and add withdrawal evidence; do not overwrite or delete the earlier decision. Withdrawal invalidates the approval's current effect, returns the enquiry to `Drafting`, and requires a new reviewed snapshot before readiness is restored.

Concurrent edits, submissions, approvals, withdrawal, and archiving must have deterministic transactional outcomes. Business state, revision/snapshot evidence, and durable audit events must commit together. Optimistic-lock/version representation, transaction design, and snapshot serialization are deferred technical decisions; these integrity requirements are not deferred.

## AI and human acceptance

AI may propose summaries, clarification questions, or draft content using only authorized minimized information for an explicit purpose. Proposals remain separate from authoritative records. AI cannot qualify an enquiry, accept its own suggestions, submit/approve a draft, publish, reserve, confirm, or process payments independently.

An authorized human sees the proposed change and its source version before accepting it. Acceptance rechecks current authority, assignment, purpose, data rules, and expected revision, then creates an attributable revision through the normal application boundary. Reject stale or unauthorized acceptance. Acceptance is not internal approval, and internal approval is not publication. Retain minimized proposal provenance and acceptance/rejection evidence under explicit retention policy.

## Audit, minimisation, and future verification

Record authorized and denied sensitive actions with safe reason categories and attributable actor, active organization, owner, resource, action, membership/grant basis, timestamp, and relevant version/snapshot. Track state transitions, assignments, collaboration, revisions, submissions, review decisions, approval, withdrawal, supersession, archiving, and AI acceptance. Limit audit access and avoid raw contacts or sensitive free text in events.

Future workflow tests must exercise every allowed transition and reject unspecified transitions; verify organization capability, assignment, purpose, and field limits; prevent self-approval; reject stale edits and stale approvals; preserve immutable review snapshots; prove withdrawal and supersession behavior; enforce atomic audit/state changes; and verify cross-tenant and concurrent-access failures. AI tests must prove that proposals alone cannot change authoritative state and that acceptance revalidates authority and version.

Future review and qualification tests must specifically prove:

- Successful `New` → `Under review` claims an unassigned enquiry for the acting membership atomically; successful `Under review` → `Qualified` requires that same current assignee and preserves it.
- Independent capability enforcement in both directions: review-only authority cannot qualify, qualification-only authority cannot start review, and creation authority or administrative status alone authorizes neither transition.
- Denial of direct `New` → `Qualified`, invalid states, repeated or skipped transitions, review of an already assigned enquiry, missing assignees, and qualification by a different membership, including another membership of the same actor.
- Denial of missing, malformed, mismatched, inactive, revoked, premature, or expired memberships/grants; exact membership validity boundaries; wrong enquiry/action grant scope; cross-organization attempts; and violations of applicable purpose or field restrictions.
- Denial of reassignment, supervisor override, delegation, bulk transitions, and AI-driven transitions. Stale expected versions or concurrent attempts must not overwrite an assignment or produce a partial state/audit outcome.
- Correct organization, enquiry, actor, membership, grant, capability, prior/new state, assignee, and timestamp attribution using multiple distinct actors and memberships. Assertions must detect hard-coded identities in both business results and audit facts. Denials and failures must preserve state, assignment, and prior audit values and return no success event; returned values must not permit mutation of authoritative facts.
- Continued acceptance of valid historical travel dates during manual capture, with travel dates never substituted for transition authorization or audit timestamps.

Deferred decisions include itinerary structure, assignment policies beyond the review self-assignment and qualification rules above, revision identifiers, snapshot serialization, database transactions and isolation, UI/API contracts, retention durations, and AI provider/proposal storage. Quotation, publication, reservations, supplier confirmation, payment, passport, and medical features require separate authorization and are not next steps implied by this specification.
