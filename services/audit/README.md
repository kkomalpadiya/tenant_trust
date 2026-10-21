# Audit outbox worker

This service keeps Fabric off the synchronous authorization path. A selected canonical event is converted to the T8.3 commitment and inserted into PostgreSQL through `audit.enqueue_fabric_commitment` in the caller's existing tenant-bound transaction. The enqueue operation never opens a Fabric connection.

The worker claims one due row through the restricted `tenant_trust_audit_outbox_worker` role, submits only the approved minimal ledger value through the backend Fabric Gateway, and records either `submitted` or a bounded retry. Claims abandoned for five minutes are recovered. If a process stops after Fabric accepts a transaction but before PostgreSQL is updated, the same commitment is submitted again and chaincode idempotency returns `duplicate`.

`submitted` deliberately means that the T8.6 delivery attempt received a valid Gateway/chaincode response. Durable transaction identity, explicit commit confirmation, reconciliation, and degraded-state reporting belong to T8.7.
