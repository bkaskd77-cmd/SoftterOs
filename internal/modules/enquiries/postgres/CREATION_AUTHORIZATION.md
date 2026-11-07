# Creation authorization prerequisite

This bounded internal component checks only `enquiries.create`. It makes no
enquiry, event or receipt writes and implements no application operation, public
endpoint, identity provider, policy administration or receipt recovery.

`NewCreationChecker(db, identity).Check(ctx, CreationRequest)` uses the existing
scoped `READ COMMITTED` transaction boundary. Trusted entry code must already
authenticate the caller and bind `ActorID` and `RequestID` to that request.
Organization and membership selectors are checked against database bindings;
neither selectors nor transaction settings establish identity or permission.
There are no caller-supplied capabilities or administrator bypasses.

The checker performs these steps on one transaction connection:

1. Acquire shared actor then organization fences using the unchanged lock-only
   SQL helper. Require both positive revisions; retain locks through completion.
2. Ask the mandatory `CreationIdentity` adapter for current actor attestation,
   bound to the same actor and request. Missing, unauthenticated, mismatched or
   unavailable attestation fails closed. No default provider is supplied.
3. Read current actor/organization/membership bindings, membership status and
   validity, and the exact effective entitlement row after lock acquisition.
   Explicit tenant predicates supplement RLS. Apply the existing Go policy.
4. Use fresh `clock_timestamp()` after those reads, then another fresh instant
   immediately before returning the transaction callback. Both policy checks must
   pass; a backward clock fails closed. Times must be finite, nonzero, in UTC
   years 1–9999 and exactly microsecond-representable. No rounding is performed.
5. Return success only after the existing transaction boundary acknowledges
   commit. Cancellation, rollback, lock deadlines and uncertain commit outcomes
   retain that boundary's semantics. No automatic retry is introduced.

Nil acknowledges this completed check. It is **not authority for a later
transaction**. No facts, contexts or creation proofs escape the checker. Future
creation persistence must compose fresh checks and writes in one transaction;
it must never call Check, release the fences and then write separately. This
read-only prerequisite queues no deferred integrity work. A future coordinator
must finish all such work before its final expiry check and retain the original
action instant. The check cannot promise validity at an unknowable future commit
or response-delivery instant.

The separately authorized [first-attempt writer](FIRST_CREATION.md) now calls the
same private fence/fact acquisition path inside its own single transaction. Its
private facts remain transaction-bound, with fresh checks after reservation waits
and after executing deferred integrity checks. It never calls standalone Check
to authorize a different transaction. Standalone Check retains its original
preflight/final checks and returns no reusable facts.

## Existing-schema semantics and trust

Actors and organizations are existence anchors. Actor enablement/revocation
remains current trusted identity attestation, not an invented database column.
Entitlement deletion revokes a capability; membership inactivity, revocation or
exclusive expiry ends its membership-derived permission. There is no independent
capability expiry/status and no change to creation's existing human-attestation
policy. The trusted identity tier must not attest AI callers for authoritative
business actions.

Every identity change must take the actor fence exclusively. Membership and
entitlement writers must take the organization fence exclusively before changing
facts, increment its revision and commit atomically. Writers affecting both take
actor then organization locks. Revocation-first denies; a transaction that gets
its shared fences first completes or rolls back before a compliant writer can
acknowledge revocation. Revisions alone do not establish freshness.

`CreationIdentity` must use a reviewed coordinated local source, honor the
operation context, and do no external network or human waiting under locks.
Cached attestations and always-allow providers violate its contract. The supplied
test double changes its synthetic status only under the exclusive actor fence;
it is not production authentication, a session verifier or a durable revocation
ledger. No provider is implemented here. External identity/policy integration,
cooperating production authority writers and untrusted request handling still
require their separately reviewed contracts.

Database failures and attestation unavailability return safe
`ErrCreationUnavailable`, retaining cancellation/deadline markers without raw
driver/provider details. Policy/binding failures return `authz.ErrUnauthorized`.
Pool/commit/cleanup errors retain the existing infrastructure categories.

## Verification

Run the [existing disposable harness](../../../../db/README.md) in normal and
race modes. New tests provision only synthetic access anchors, memberships,
entitlements and fences. Restricted effective role switching and the privileged
fixture bootstrap exist solely in tests; they do not establish runtime-login
authentication or protection against a compromised database administrator.
The privileged-login/no-capability case verifies that Go grants no implicit
administrative permission, not that administrators cannot alter policy tables.

Tests cover policy denials, independent actor/request binding, post-wait reads,
both revocation orderings, commit/rollback lock release, exact expiry and expiry
during fence waits/final checks, cancellation, SQL lock deadlines and clean pool
reuse. Real lock and server-clock predicates provide synchronization. No test
changes schema constraints, authentication configuration or lifecycle helpers.

The [persistence design](../../../../docs/ENQUIRY_PERSISTENCE_DESIGN.md) remains
proposed outside separately approved slices. Workflow writes, atomic durable
business/audit storage, stored-version command orchestration, receipts, external
authentication, API/UI and deployment remain deferred.
