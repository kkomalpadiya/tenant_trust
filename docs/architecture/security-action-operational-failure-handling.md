# Security-action operational failure handling

T9.9 adds one least-privilege operational boundary across durable security-action execution and the T9.7 Fabric audit path. An action is healthy only when execution is no longer stuck or retrying and every immutable action-audit expectation has reached `committed` in the Fabric outbox.

## Visible failure states

`orchestration.list_security_action_operational_issues` reports bounded, ordered issues without granting operators direct table access:

- an expired execution lease is `ACTION_LEASE_STUCK` and critical;
- an overdue unclaimed action is `ACTION_PENDING_STUCK`;
- a retryable execution failure, including a failed CA call, is `ACTION_RETRY_SCHEDULED` with its stable action ID, attempt count, failure code and next retry time;
- a deliberately suppressed redundant or stale action remains visible as informational `ACTION_SUPPRESSED`;
- an unexpected non-retryable failure is `ACTION_TERMINAL_FAILURE` and critical;
- each audit expectation remains visible as unprojected, pending, stuck or failed until its Fabric outbox row is committed.

This is a current-state operations view. Immutable attempt and audit-event tables retain the historical record after an issue clears.

## Restart recovery

`orchestration.recover_expired_security_action_leases` is an idempotent startup sweep. It changes only actions whose 300-second lease has expired. The exact executing attempt becomes failed with `ACTION_LEASE_EXPIRED`, and the same action becomes immediately retryable without changing its target security state, expected state version, action ID or earlier attempt history. A repeated sweep recovers zero rows.

The existing claim path still performs the same lease recovery defensively. A worker deployment should invoke the explicit startup sweep before beginning its normal claim loop so a restart is immediately observable and does not depend on the next claim call.

## Audit-aware health

Successful action execution does not hide an audit outage. Requested, failed and succeeded action expectations are joined to their exact Fabric outbox events. Missing projection, failed submission, abandoned submission/confirmation leases and overdue confirmation remain operational issues. Only `committed` clears an audit expectation from the report.

The operator role can execute the recovery and reporting functions but cannot read or update the underlying action, attempt, audit-event or outbox tables. Existing action-worker and audit-worker roles keep their separate responsibilities.

## Commands and verification

- `npm run security-action-operations:status` performs a read-only health inspection. It exits with code 2 when any critical issue exists, making it suitable for a scheduler or alert probe.
- `npm run security-action-operations:recover` performs the idempotent expired-lease startup sweep and then prints the same health report.
- `npm run security-action-operations:verify` runs the orchestrator tests, applies migrations and executes a rollback-only PostgreSQL scenario covering crash visibility, repeated restart recovery, stable retry identity, state preservation and audit-delivery-gated health.

These controls provide durable visibility and recovery semantics. Production paging destinations, retention targets and service-manager configuration remain deployment concerns.
