# Internal first-attempt manual creation

`NewFirstCreator(db, identity, secret, newID).Create(ctx, request, requestKey, input)`
is a bounded synthetic-data persistence component. Trusted entry code must
authenticate and bind the actor/per-attempt request before calling it. It supplies
no identity provider, endpoint or permission claims from input. Its mandatory
identity adapter follows the [creation authorization contract](CREATION_AUTHORIZATION.md).

The constructor copies an explicitly configured exactly 32-byte fingerprint
secret. There is no default, automatic runtime key generation, secret logging or
key store. The trusted local ID generator is injected, concurrency-safe and must
return promptly without network/user work under locks; it generates one enquiry
ID and one event ID after authorization and validation. No production generator
is selected here. The [approved fingerprint version-1 contract](../../../../docs/ENQUIRY_PERSISTENCE_DESIGN.md#approved-first-attempt-creation-fingerprint-contract)
defines every byte and exclusion. Fingerprints are neither authorization nor
uniqueness keys; production key storage/rotation and retained-receipt verification
remain unresolved. Encoding version is not key version.

## One transaction

1. Use the unchanged scoped READ COMMITTED boundary and its finite budgets.
2. Acquire actor then organization shared fences, attest current actor/request,
   read current bindings/entitlements, and check existing Go creation policy with
   fresh database time. These locks stay held through transaction completion.
3. Validate exact input and compute its keyed fingerprint from verified bindings.
   Reserve the scoped receipt key using its existing uniqueness constraint.
4. After a possible reservation wait, obtain fresh time and recheck authority.
   Call the existing application/domain creator: New, unassigned, version 1,
   owner/creator/membership derived from the verified context. Preserve the
   original action instant in enquiry and event. Calendar dates stay separate.
5. Insert the enquiry and immutable initial event, including the retained fence
   revisions. Obtain a fresh, nondecreasing valid instant for receipt completion,
   and complete exactly the reserved receipt with matching event/resource facts.
6. Execute `SET CONSTRAINTS ALL IMMEDIATE`, then make the final fresh expiry check.
   Perform no further data writes. Return values only after acknowledged commit.

All queries are parameterized and tenant-bound. There is no standalone Check-then-
write path. Creation accepts valid historical dates and the full calendar range
0001-01-01 through 9999-12-31, with absent pairs mapped to SQL NULL. No timezone
conversion or timestamp sentinel is applied to dates. Database instants are
validated as finite, nonzero, Go-range, exact microseconds before reuse in writes.
The domain's nanosecond snapshot rules are unchanged.

## Duplicate requests and outcomes

The key scope is `(organization_id, membership_id, request_key)`. Existing keys
return `ErrDuplicateCreation` with an empty result even for identical payloads;
no stored receipt/result is returned or rewritten. An uncommitted reservation can
block within configured limits. If it commits, its competitor rejects; if it
rolls back, a still-authorized waiter may become the first committed creation.
Lock timeout/cancellation is a failed attempt, not proof of a committed duplicate.
Generated-ID collisions remain storage failures, not receipt-key duplicates.

Nil means commit was acknowledged. Every error returns zero Created, never a
partial enquiry, success audit or event ID. Preserve existing `ErrCommitRejected`
(confirmed rollback), `ErrCommitUnknown` (uncertain outcome) and `ErrCleanup`
(cleanup not confirmed). Callback failures without cleanup failure are rolled
back by the existing boundary; connection/configuration failures need not have
begun a transaction. Never describe every error as a confirmed rollback. No retry,
receipt replay/recovery or ambiguous-outcome reconciliation is implemented. Do
not automatically resubmit with another key after an uncertain outcome.

Storage errors and identifier-provider failures expose safe categories, not raw
SQL, constraint values, input, secrets or other tenants' existence. This contract
does not promise authority at an unknowable future commit/delivery instant.

## Verification and limits

Use the existing `scripts/test-postgres-go.py` harness in normal and race modes
and the standalone SQL suite. Fixtures use ephemeral random keys stable across
attempts, synthetic input and restricted effective runtime roles. Coordinated
revocation fixtures use exclusive fences. This is test-only role switching, not
genuine runtime-login authentication. Unit vectors use fixed public keys with
independently checked canonical bytes/MACs; simulated completion errors establish
result classification, not a real lost network acknowledgement. Real database
tests establish committed round trips, uniqueness contention and rollback of all
three records after injected failures, cancellation or expiry.

No schema, migration, domain policy, transaction infrastructure, lifecycle helper
or dependency change is part of this slice. Review/qualification persistence,
production authority writers/identity, replay/recovery, real-data safeguards,
HTTP/UI and deployment remain deferred.
