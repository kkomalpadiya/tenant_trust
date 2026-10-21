# Fabric topology and tenant audit permissions

This design fixes the network boundary for the two-tenant audit prototype. It does not start Fabric, create identities, deploy chaincode or claim that any record has reached a ledger. Those implementation steps begin with T8.2. The machine-readable source for the selected names, memberships and policies is `config/fabric-topology.json`.

## Design goals

- Keep Tenant Alpha and Tenant Beta ledger blocks, state and transaction metadata separate.
- Let the platform submit selected commitments asynchronously without giving browser or SaaS certificate identities direct ledger access.
- Give each tenant an independent peer and an identity that can verify only that tenant's commitments.
- Require both the platform peer and the affected tenant peer to endorse a write.
- Keep raw evidence, policy inputs, detailed decisions, certificate data, subject IDs and resource IDs off-chain.
- Fit the local demonstration resource budget without presenting the topology as production-ready or highly available.

## Organizations and nodes

| Organization | Local nodes | Responsibility |
| --- | --- | --- |
| `TenantTrustOrdererMSP` | `orderer0.audit.tenant-trust.test` | A separate ordering organization runs one Raft orderer for the local prototype. It serves both tenant channels and has no peer or chaincode identity. |
| `PlatformAuditMSP` | `peer0.platform.audit.tenant-trust.test` | The platform peer joins both audit channels. Separate client identities submit commitments, confirm commits and perform reconciliation or verification. |
| `TenantAlphaAuditMSP` | `peer0.alpha.audit.tenant-trust.test` | The Alpha peer joins only the Alpha audit channel and retains Alpha's copy of the commitment ledger. |
| `TenantBetaAuditMSP` | `peer0.beta.audit.tenant-trust.test` | The Beta peer joins only the Beta audit channel and retains Beta's copy of the commitment ledger. |

Every MSP uses its own Fabric CA enrollment boundary. Fabric enrollment, TLS and client certificates are distinct from the step-ca certificates used to authenticate SaaS requests. Generated Fabric keys, certificates, MSP directories, wallets and channel artifacts stay under ignored runtime storage and never enter Git.

The initial peers use LevelDB because the audit contract needs deterministic key lookup rather than rich JSON queries. One peer per peer organization and one orderer keep the local network small. The single Raft orderer has no failover and therefore supports only development and evaluation. A production-style deployment needs at least three orderers across independent failure domains before it can claim ordering-service high availability.

## Tenant channels

| Channel | Peer organizations | Ordering organization | Other tenant excluded |
| --- | --- | --- | --- |
| `tt-audit-alpha-v1` | `PlatformAuditMSP`, `TenantAlphaAuditMSP` | `TenantTrustOrdererMSP` | `TenantBetaAuditMSP` |
| `tt-audit-beta-v1` | `PlatformAuditMSP`, `TenantBetaAuditMSP` | `TenantTrustOrdererMSP` | `TenantAlphaAuditMSP` |

Fabric channels carry separate ledgers and admit only configured member organizations. A Beta peer therefore receives no Alpha blocks or state, and an Alpha peer receives no Beta blocks or state. The audit service selects the channel from the server-validated tenant ID through a closed mapping. Requests, event payloads, client headers and resource identifiers cannot name or override a Fabric channel.

The network uses the channel participation API and no deprecated ordering-service system channel. The platform peer and the tenant peer are anchor peers on their shared channel. The orderer joins both application channels, but it does not host world state or execute chaincode.

### No application private-data collections in v1

The initial chaincode defines no application private-data collections. Each tenant already has a separate channel, and the only public state permitted on that channel is a minimal audit commitment. Adding collections would increase lifecycle, gossip and reconciliation complexity without hiding transaction activity from the two organizations that already share that tenant's channel. Fabric still records private-data hashes in the common channel ledger, so collections would not replace the cross-tenant block isolation provided by separate channels.

T8.3 will define the exact commitment preimage and event-selection rules. This topology only fixes the placement boundary: raw telemetry and detailed application records remain in tenant-scoped off-chain storage, while the ledger receives opaque event identities, cryptographic commitments and the minimum anchors required for later verification. Plain tenant, subject and resource identifiers are forbidden in ledger state and transaction arguments.

## Governance and endorsement

Each channel has two application organizations: the platform and that channel's tenant organization.

- `Readers` and `Writers` recognize members of either channel organization so Fabric Gateway, discovery and delivery can operate. Function-level chaincode checks narrow this broad network policy.
- `Admins` requires both the platform administrator and the tenant organization administrator. Neither side can change channel membership or application policies alone.
- `LifecycleEndorsement` requires a peer from both channel organizations. Both organizations must approve chaincode definitions and collection changes.
- The audit chaincode endorsement policy requires `AND('PlatformAuditMSP.peer','Tenant...AuditMSP.peer')`. A commitment cannot become valid with only a platform endorsement or only a tenant endorsement.
- Ordering-service configuration remains under the separate `TenantTrustOrdererMSP` administration boundary. Application organizations do not receive orderer administrator credentials.

The explicit two-peer endorsement policy improves tamper resistance inside the demonstration, but it also means either peer being unavailable pauses new ledger commitments. The protected SaaS request path still uses PostgreSQL, Redis and OPA. Ledger outages leave durable audit work pending and visible rather than weakening an authorization decision.

## Client identities and chaincode permissions

Fabric CA enrollment certificates carry the `tenantTrust.role` attribute. Channel membership establishes which ledger an identity can reach; chaincode authorization establishes which contract function it can call.

| Role | MSP | Allowed capability |
| --- | --- | --- |
| `audit-writer` | `PlatformAuditMSP` | Submit a commitment through the asynchronous audit worker. It cannot administer a channel or query arbitrary off-chain data. |
| `audit-commit-listener` | `PlatformAuditMSP` | Receive commit status for reconciliation. It does not submit commitments. |
| `audit-verifier` | `PlatformAuditMSP` | Query commitments on either tenant channel for controlled reconciliation and causal verification. |
| `tenant-auditor` | The corresponding tenant audit MSP | Query commitments and receive events only on that tenant's channel. It cannot submit commitments or reach the other tenant's channel. |
| Organization administrator | Its own MSP | Perform channel and chaincode lifecycle administration. An administrator identity is never used by the application worker. |

SaaS users, tenant application administrators, browsers and the mTLS gateway receive no Fabric credentials. Later API audit views must use the protected application authorization path rather than passing a ledger identity to a browser.

T8.4 must enforce the role attribute and the invoker MSP inside every chaincode function. Channel `Writers` membership alone is not permission to append an audit record. The chaincode must also compare its channel ID with the commitment's trusted tenant binding and reject a cross-channel or caller-selected tenant value. T8.5 must hold each client key outside the repository and construct the Gateway target from the same closed tenant-to-channel mapping recorded in this design.

## Visibility boundary

| Information | Platform audit peer | Matching tenant peer | Other tenant peer | Ordering node |
| --- | --- | --- | --- | --- |
| Tenant channel blocks and public commitment state | Yes | Yes | No | Receives and orders that channel's transaction envelopes and blocks |
| Commitment preimage and detailed application record | Off-chain access only through the audit service's constrained data path | No direct ledger copy | No | No |
| Raw signed evidence or decrypted telemetry | No ledger copy | No ledger copy | No | No |
| Other tenant's channel blocks and state | The platform peer is deliberately joined to both channels | No | No | The shared orderer serves both channels |
| Fabric private keys | Only the key for the assigned platform identity | Only keys issued by its own Fabric CA | Only keys issued by its own Fabric CA | Only orderer enrollment and TLS keys |

The shared platform peer and orderer are broad trust boundaries for commitment metadata. Their compromise can expose transaction timing, volume and opaque commitments for both tenants. The design limits the impact by excluding raw and identifying data, separating worker identities from administrators and requiring the matching tenant peer to endorse writes. It does not claim independence from a compromised local host or platform operator.

## Transaction and failure path

1. The audit worker receives a durable, selected off-chain audit item after its originating transaction commits.
2. Server-validated tenant context selects exactly one configured channel. The worker cannot accept a channel name from an event or caller.
3. The platform Gateway identity proposes the commitment to the platform peer. Fabric Gateway gathers the platform and matching tenant peer endorsements required by the channel's chaincode policy.
4. The worker submits the endorsed transaction to the Raft orderer and waits for peer commit status. An orderer acknowledgement alone never marks the item committed.
5. PostgreSQL records the Fabric transaction ID, block position and validation result only after commit confirmation. Timeouts, invalid commits and outages remain pending or failed for T8.7 reconciliation.

This sequence is a design contract for later tasks. T8.1 does not implement or verify the transaction flow.

## Handoff to the remaining Phase 8 tasks

- T8.2 will pin image digests and Fabric CA tooling, generate ignored identities, create both channels and prove the selected nodes start reproducibly.
- T8.3 will define selected event types, canonical commitment bytes, identifiers and disclosure-minimizing fields.
- T8.4 will implement duplicate protection, channel binding, MSP and role checks, query authorization and the two-organization endorsement policy.
- T8.5 will create the least-privilege Gateway clients and the closed tenant-to-channel adapter.
- T8.6 through T8.10 will add durable delivery, commit reconciliation, causal verification, privacy/tamper tests and outage recovery.

## Verification

Run:

```text
npm run fabric-topology:verify
```

The verifier checks unique MSP and node names, the two seed-tenant mappings, strict per-tenant channel membership, exclusion of the other tenant MSP, two-organization endorsement and administration, role-scoped submit/query/listen permissions, the absence of v1 private-data collections, the off-chain data boundary and the explicit single-orderer availability limitation.

## Fabric references

- [Channels and separate ledgers](https://hyperledger-fabric.readthedocs.io/en/release-2.5/create_channel/create_channel_overview.html)
- [Channel policies and governance](https://hyperledger-fabric.readthedocs.io/en/release-2.5/create_channel/channel_policies.html)
- [Endorsement policies](https://hyperledger-fabric.readthedocs.io/en/release-2.5/endorsement-policies.html)
- [Raft ordering service and quorum](https://hyperledger-fabric.readthedocs.io/en/release-2.5/orderer/ordering_service.html)
- [Private-data hashes and collection access](https://hyperledger-fabric.readthedocs.io/en/release-2.5/private-data-arch.html)
- [Fabric Gateway endorsement flow](https://hyperledger-fabric.readthedocs.io/en/release-2.5/gateway.html)
- [Fabric CA attribute-based access control](https://hyperledger-fabric-ca.readthedocs.io/en/latest/users-guide.html#attribute-based-access-control)
