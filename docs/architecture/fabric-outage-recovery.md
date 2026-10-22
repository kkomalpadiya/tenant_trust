# Fabric outage and recovery

Fabric is a durable verification sink, not part of the synchronous authorization decision. A protected request still depends on current certificate, tenant, membership, trust and OPA state. Once an `access.decided.v1` event is selected for the ledger, its commitment is inserted into PostgreSQL in the caller's tenant-bound transaction without opening a Fabric connection. PostgreSQL enqueue failure therefore fails the local transaction, while Fabric unavailability does not weaken or replace the authorization result.

The asynchronous worker uses at-least-once delivery with commit reconciliation. A submission outage leaves the row visibly `failed`, preserves its attempt count and bounded failure code, and schedules a retry. If submission succeeded but confirmation was lost, the row remains `submitted` with its immutable Fabric transaction ID so a restarted worker can query QSCC instead of creating an ambiguous second result. An event is `committed` only after validation code `0` is recorded.

## Controlled recovery gate

Run the following with the core development stack and Fabric network healthy:

```powershell
npm run fabric-outage-recovery:verify
```

The gate performs a real, reversible outage of `peer0.alpha.audit.tenant-trust.test`. Because the Alpha channel requires both platform and Alpha endorsements, new Alpha commitments cannot complete during that outage. While the peer is stopped, the gate:

1. runs the deterministic adaptive-authorization scenario and proves its ALLOW and QUARANTINE outcomes still complete;
2. writes a contract-valid access-decision commitment to the PostgreSQL outbox;
3. runs the real Gateway worker and proves the failed submission is present in the bounded operator gap view;
4. restarts the peer and waits for its health check;
5. retries the exact outbox event, confirms validation code `0`, reads the commitment through the verifier identity, and compares it with the stored PostgreSQL ledger value; and
6. confirms the bounded gap view is empty.

The script restores the tenant peer in a `finally` block if an assertion fails and removes its disposable outbox row. The immutable test commitment remains on the local development ledger, as expected for Fabric. This gate proves recovery behavior for the single-node local prototype; it does not claim production high availability. The production topology still needs at least three orderers and appropriately redundant peers, monitoring and alerting.

## Operational response

- Keep the authorization path operating only while its own fail-closed dependencies remain healthy. Do not substitute a stale Fabric result for current policy state.
- Monitor `npm run audit-outbox:status`; `pending`, `submitting`, `submitted`, `confirming` and `failed` rows are explicit delivery gaps.
- Restore endorsement and ordering availability before forcing retries. Never mark a row committed by hand.
- Reconcile `submitted` rows by transaction ID. Retry `failed` rows through the worker's idempotent commitment key.
- Verify the recovered ledger value against the durable off-chain event and investigate any remaining or newly aged gap.
