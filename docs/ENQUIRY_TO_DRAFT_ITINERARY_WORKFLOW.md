# Enquiry to internally approved draft itinerary

## Boundary and implementation status

This workflow starts with manual enquiry capture and ends with an internally approved draft itinerary. It excludes quotation, publication, reservations, supplier confirmation, and payment processing. Passport and medical-data collection are outside the workflow.

Only manual enquiry creation is implemented by this foundation. Qualification, drafting, state transitions, assignments, revisions, review, and approval below are requirements for future bounded work. There is no HTTP interface, database, durable audit log, frontend, AI integration, or traveller delivery mechanism.

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

Deferred decisions include itinerary structure, assignment policies, revision identifiers, snapshot serialization, database transactions and isolation, UI/API contracts, retention durations, and AI provider/proposal storage. Quotation, publication, reservations, supplier confirmation, payment, passport, and medical features require separate authorization and are not next steps implied by this specification.
