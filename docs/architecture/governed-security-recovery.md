# Governed security recovery and re-enrollment

T9.6 turns the eligibility decision from T9.2 into an authenticated, durable recovery workflow. Eligibility alone has no effect. A current tenant administrator must present a fresh, single-use `tenant:admin` step-up proof, and the request must bind to the current trust transition and current security-state version before a recovery action enters the T9.3 queue.

## Authorization boundary

`createGovernedRecoveryService` accepts only a trusted tenant context with the `tenant-admin` role. It loads the target's current composite security posture and trust checkpoint, loads active severe evidence through the configured evidence repository, and calls the T9.2 evaluator. The service derives the action; callers cannot choose `restore-access` or `issue-replacement-certificate`.

The PostgreSQL authorization function independently verifies:

- the authenticated actor is a current administrator in the same tenant;
- the single-use step-up proof is bound to that actor, session, request and `tenant:admin` action;
- the supplied trust transition is still the subject's current transition, is no more than five minutes old, records a completed recovered transition, and carries the two-source/two-evaluation evidence required by T6.6;
- the target posture still has the exact state version evaluated by the service;
- suspended or renewal-blocked recovery has a high-band score of at least 75, while restriction-only recovery needs a medium-or-higher band and score of at least 45; and
- a revoked target has an explicit cause-resolution reference.

The proof consumption, append-only authorization record and recovery action enqueue occur in one transaction. A tenant/actor-scoped idempotency key returns the original authorization on an exact replay and rejects changed intent. The authorization expires after five minutes. Direct access to the authorization table is denied to application and worker roles.

## Two-stage recovery after revocation

Revocation is permanent. The first authorized action calls an injected certificate-issuance adapter. The worker accepts confirmation only for a different certificate ID in `active` state. PostgreSQL then verifies that the replacement exists in the same tenant, belongs to the same subject, was issued after authorization and was requested by the authorizing administrator. Only then does the composite posture move from `replacement=required` to `replacement=issued`.

Access remains suspended and renewal remains blocked after replacement issuance. A second current recovery evaluation and a second single-use step-up proof are required for `restore-access`. That action changes only access and renewal. The original target certificate remains `revoked`, and the distinct replacement remains independently represented in the certificate inventory.

The injected replacement adapter must obtain and verify a fresh subject key/CSR through the T3.3 certificate issuance boundary. It must never reuse the revoked certificate, its identifier or private key. Active severe-evidence loading is also an integration requirement; an unavailable evidence source must fail closed instead of returning an empty list.

## Verification

Run `npm run security-recovery:verify`. The gate runs the orchestrator unit suite, applies migrations and executes a rollback-only PostgreSQL scenario. It proves administrator and step-up enforcement, current trust/state binding, exact replay, worker authorization metadata, rejection of the revoked target as its own replacement, distinct active replacement issuance, a separately authorized access restoration, and permanent revocation of the original certificate.
