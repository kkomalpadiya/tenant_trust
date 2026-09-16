# Session, timeout and replay safeguards

## Stateless authenticated requests

Protected API requests use the client-certificate identity authenticated by the mTLS gateway. The API does not create or resume an application session: any `Cookie` or `Authorization` header is rejected before protected data access, and protected responses carry `Cache-Control: no-store` and `Pragma: no-cache`. Certificate and tenant state are still revalidated in a new transaction for every request.

The API accepts at most 4 KiB of request-body data. Sensitive exports additionally accept 1–25 unique record IDs. Schema validation rejects extra fields, query controls and caller-supplied tenant, actor, authorization, mode or operation identifiers.

## Bounded execution

Each protected operation has a five-second end-to-end deadline. Repository transactions use a four-second PostgreSQL statement timeout, a one-second lock timeout and a matching idle-in-transaction timeout. The request abort signal reaches all repository queries and the trusted sensitive-operation authorizer. A timeout cancels pending work, rolls back the transaction and returns the bounded `503 SERVICE_UNAVAILABLE` response; it never reuses an earlier allow decision or commits a partial idempotency receipt.

## Sensitive-operation replay control

Both sensitive `POST` routes require an `Idempotency-Key` in the exact form `idem_<UUID>`. The raw key is never stored. PostgreSQL stores only its SHA-256 digest, the normalized request digest and a server-generated operation ID under the authenticated tenant, actor and action. Reservation occurs inside the same transaction as state revalidation, authorization and the protected query.

An identical retry in the same tenant/actor/action scope reuses the original operation ID and marks response metadata with `idempotentReplay: true`. Reusing a key for different normalized input returns `409 IDEMPOTENCY_CONFLICT`. Another tenant, actor or action has a distinct namespace. The runtime role has execute-only access to the constrained reservation function and no direct receipt-table privileges.

## Verification

`npm run request-safeguards:verify` runs API unit coverage, validates migration ownership and privileges, and exercises live PostgreSQL replay, conflict, ambient-session rejection, request-size rejection and timeout rollback. The verifier removes its durable receipts. `npm run foundation:check` and `npm run foundation:clean` include the same checks.
