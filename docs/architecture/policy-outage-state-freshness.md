# Policy outage and state-freshness controls

## Fail-closed policy dependency

Every adaptive authorization request has two nested deadlines: the API request remains bounded to five seconds, while the OPA exchange—including response parsing—has an independent maximum of 1,500 milliseconds. Transport failure, timeout, non-success response, malformed output, missing active bundle or decision/state binding mismatch raises a policy-unavailable result. The API returns only `503 SERVICE_UNAVAILABLE` with `Cache-Control: no-store`; the bounded internal reason is retained in the request audit event and is not exposed in the response.

There is no last-known-good allow path. The policy client stores no decision cache, `allowCacheOnOutage` is fixed to `false`, and a retry is a new request that must load current authority, certificate, trust and active-bundle state again.

## Trust freshness at the decision boundary

The PostgreSQL trust lookup remains the authoritative age calculation. Missing or stale state carries `requiredOutcome: DENY` and no usable policy score. OPA must return the matching explicit `DENY`; an `ALLOW`, `STEP_UP` or `QUARANTINE` response cannot override that constraint.

A state that was fresh when loaded can cross its configured boundary while bundle lookup or OPA evaluation is running. The enforcement service therefore records a monotonic timestamp at lookup and, after validating the complete OPA response, adds the elapsed decision time to the authoritative database age. If the combined age exceeds `staleAfterSeconds`, the request fails with internal reason `TRUST_STATE_EXPIRED_DURING_DECISION` before any protected query runs. The exact boundary remains usable; only an age greater than the limit fails.

## Certificate lifecycle serialization

Migration `028_policy_state_freshness_controls.sql` adds `identity.lock_current_actor_certificate_status`. This security-definer function accepts only the presented certificate identity, derives tenant and subject from the transaction-bound actor, returns at most that actor's exact certificate row and takes a PostgreSQL share lock on it. The runtime role receives only function execution and still has no direct certificate `UPDATE` privilege.

The share lock is held through the protected query and transaction commit. A concurrent revocation, expiry or supersession update must wait for the already-authorized bounded transaction to finish; it cannot change the certificate midway through that request. Once the lifecycle update commits, the next request performs a new authoritative lookup, sees the new version/state and denies. No certificate allow result is reused across requests.

## Verification

After `npm run infra:migrate`, run `npm run policy-resilience:verify`. The gate covers timeout and response sanitization, stale and in-flight-expiring trust, constrained certificate lookup, least-privilege grants, concurrent lifecycle locking, next-request certificate/tenant/membership invalidation, OPA policy tests and the authoritative trust lookup.
