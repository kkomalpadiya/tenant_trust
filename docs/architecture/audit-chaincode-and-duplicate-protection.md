# Audit chaincode and duplicate protection

T8.4 deploys the `tenant-trust-audit` TypeScript chaincode to both tenant audit channels. It runs as three isolated Chaincode-as-a-Service containers—one beside the Platform peer and one beside each tenant peer—so the peers do not need the Docker socket. Every peer installs the same deterministic connection package; the embedded external builder resolves the package's templated endpoint to that peer's chaincode service.

## Public state

`CommitCommitment` accepts one JSON argument containing exactly the six public fields defined by T8.3. It derives all keys itself and rejects additional properties, malformed hashes, unknown record classes and unsupported contract versions.

The transaction atomically writes:

```text
audit~<recordType>~<eventKeyHashSha256> -> <canonical six-field commitment JSON>
event~<eventKeyHashSha256>             -> <the commitment key above>
```

The second record is the minimum event anchor. It prevents one opaque event key from being reused with another record class. Neither key or value contains a plain tenant, subject, resource, certificate, decision, action or event identifier.

If both records already contain the exact expected bytes, the method returns `duplicate` and produces no state write or chaincode event. If either record is missing while the other exists, the method fails closed. A changed commitment at the same key raises `CONFLICTING_COMMITMENT`; reuse of the event anchor under a different record class raises `CONFLICTING_EVENT_ANCHOR`. Fabric MVCC and the channel endorsement policy handle concurrent proposals, while the deterministic checks make retries safe.

## Authorization and endorsement

The contract accepts writes only when the invoker belongs to `PlatformAuditMSP` and its Fabric CA certificate carries `tenantTrust.role=audit-writer`. Reads require either the Platform `audit-verifier` role or the `tenant-auditor` role from the tenant MSP paired with the current channel. Administrators, writers, listeners and the other tenant's auditor receive no implicit query privilege.

Both channel definitions use `/Channel/Application/Endorsement`. With the two-member channel profiles this requires matching execution by the Platform peer and the tenant peer. The lifecycle definition is approved by both channel organizations before it is committed. The chaincode emits `AuditCommitmentCreated` only for a new record and includes only the already-public key, record class and opaque hashes.

## Operational boundary

`npm run fabric:up` now packages, installs, approves and commits the definition idempotently, builds the digest-pinned Node 22 chaincode image and starts all three external services. `npm run fabric-chaincode:verify` checks the local contract tests, network definition, committed definitions on both channels, writer and reader roles, exact duplicate behavior, conflicting duplicate rejection and channel isolation.

This task deliberately does not add a backend Fabric Gateway client or an asynchronous application outbox. Those are T8.5 and T8.6.
