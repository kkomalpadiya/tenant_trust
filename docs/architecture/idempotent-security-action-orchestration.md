# Idempotent security-action orchestration

T9.3 turns authorized T9.1/T9.2 action decisions into durable, retryable work without rewriting the append-only request evidence created by T7.6. Each action keeps its original `act_...` identifier from request through every attempt and terminal result.

## Durable model

`orchestration.security_actions` is the queue and current execution receipt. It records tenant, subject, certificate, decision, correlation, authority, expected state version, lease ownership, retry schedule, last failure and terminal result. `orchestration.security_action_attempts` preserves each claim and its outcome. `orchestration.subject_security_states` stores the composite access, renewal, target-certificate and replacement posture defined by T9.1.

An `AFTER INSERT` trigger mirrors each append-only `audit.security_action_requests` quarantine request into the execution queue. Severity actions use a separate least-privilege function and must bind to matching tenant-scoped `QUARANTINE` decision provenance with a trust transition. Exact replays return the existing action; conflicting reuse of the semantic decision/action key fails closed.

## Claims, retries and completion

Workers claim due work with `FOR UPDATE SKIP LOCKED`. A claim has a 300-second lease and a unique token. Only that token can finish the attempt. Expired leases become visible failures and can be reclaimed. Failures retain the same action ID and use exponential delays starting at five seconds, capped at ten minutes.

Completion locks the target posture and compares its version with the version captured at claim time. The database independently derives the permitted next state and rejects a mismatched result. Certificate revocation additionally requires the T3.7 inventory to already report the exact target certificate as `revoked`; an external event reference is retained with the action. Recovery actions remain non-executable until T9.6 supplies authenticated recovery authorization.

Direct table access is denied to the application, requester and worker roles. The requester can only enqueue severity actions through its validated function. The worker can only claim, complete, fail and read a tenant/action-bounded status through security-definer functions.

## Verification

Run `npm run security-action-orchestration:verify`. It runs the complete orchestrator unit suite, applies pending migrations and executes a rollback-only PostgreSQL gate proving stable IDs, exact replay behavior, claim ownership, retry visibility, per-attempt history and versioned terminal state.
