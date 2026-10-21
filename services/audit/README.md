# Audit outbox worker

This service keeps Fabric off the synchronous authorization path. A selected canonical event is converted to the T8.3 commitment and inserted into PostgreSQL through `audit.enqueue_fabric_commitment` in the caller's existing tenant-bound transaction. The enqueue operation never opens a Fabric connection.

The worker claims one due row through the restricted `tenant_trust_audit_outbox_worker` role, submits only the approved minimal ledger value through the backend Fabric Gateway, durably records the Fabric transaction ID, and marks the event `committed` only after validation code `0` is confirmed. Invalid commits and submission failures remain visibly `failed` with a bounded retry.

If a worker stops or loses the commit-status response after submission, the transaction remains `submitted`. A restarted worker claims that gap and queries QSCC by transaction ID to recover the validation code and block number without resubmitting. Five-minute submission and confirmation leases are recovered independently, and every submitted transaction attempt is retained in `audit.fabric_commitment_attempt`.

Run `npm run audit-outbox:status` to show the state summary and a bounded list of all pending, in-flight, reconciliation, and failed gaps. The status command uses constrained security-definer functions and does not grant direct table access.

The causal verifier independently rebuilds each commitment from the durable off-chain event, compares it with both the stored outbox value and the value read through the Fabric verifier identity, and then checks the evidence, trust transition, active policy, decision and target-certificate action links. Its PostgreSQL role can call only tenant-and-correlation-bounded reader functions; it has no direct table access. Run `npm run causal-audit:verify` with PostgreSQL and Fabric running to exercise the database boundary, live ledger reads, a complete five-record causal chain and a rejected tampering attempt.
