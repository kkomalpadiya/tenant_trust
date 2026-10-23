# Security-action and recovery audit anchoring

T9.7 connects the authoritative T9.3/T9.6 action state to the T8 Fabric audit pipeline. PostgreSQL automatically appends an immutable audit expectation when an action is requested and whenever an execution attempt succeeds or fails. The application and action worker cannot write or rewrite these expectations.

## Durable projection

`audit.security_action_audit_events` stores one stable event ID for each action lifecycle point. A requested event uses attempt `0`; every failed or succeeded event uses the persisted action-attempt number. Normal containment and severity requests retain their exact access-decision reference. Governed recovery requests retain the recovery authorization, recovered trust transition, authorizing administrator and cause-resolution reference.

The restricted `tenant_trust_security_action_audit_projector` role can only:

1. read one ready, unanchored expectation through `audit.get_pending_security_action_audit_event()`; and
2. submit the exact schema-valid event and canonical commitment through `audit.record_security_action_audit_commitment(...)`.

The database independently compares the event identity, action fields, recovery metadata, timestamps and causation against the immutable source. It rejects a missing prerequisite or altered event before atomically inserting the commitment into `audit.fabric_commitment_outbox`. Exact retries reuse the same event ID and commitment. The existing T8.6/T8.7 worker then submits the minimal six-field ledger value and reconciles commit status.

Projection waits without discarding state when its cause is not yet present. Requested policy/severity actions wait for the matching `access.decided.v1` outbox record. Recovery requests wait for the exact recovered `trust.updated.v1` record. Terminal events wait for the requested action event. Successful revocation or replacement events also wait for the matching certificate lifecycle event. Ready events from other actions remain projectable.

Run the projector and Fabric delivery worker as separate processes:

```text
npm run security-action-audit:projector
npm run audit-outbox:worker
```

## Verification

The verifier role has no direct table access. Correlation-bounded functions expose the immutable expectations and only the matching action, cause and certificate outbox records. `createSecurityActionAuditVerifier` then:

- recomputes every off-chain commitment and compares it with Fabric;
- requires every authoritative expectation to have exactly one committed action event;
- rejects extra, missing or field-mismatched action events;
- links policy/severity requests to the exact decision and target certificate;
- links governed recovery requests to the exact recovered trust transition;
- links terminal events to the requested action event; and
- links successful revocation or replacement to the exact revoked or newly issued certificate event.

This proves that the committed bytes match the authoritative action history and that the declared causal references exist. It does not prove that the original evidence was truthful. Raw evidence, administrator proof material and cause-resolution case contents remain off-chain.

Run `npm run security-action-audit:verify` for contract and audit tests, migration application, the rollback-only least-privilege/database scenario and the two-stage governed-recovery capture scenario.
