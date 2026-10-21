# Reproducible private Fabric network

T8.2 implements the T8.1 topology as a local, private Hyperledger Fabric network. It starts four independent Fabric certificate authorities, one Raft orderer and one peer for each of the platform, Tenant Alpha and Tenant Beta audit organizations. It creates the two tenant audit channels without deploying chaincode or defining audit commitment fields.

## Pinned runtime

The network uses the following reviewed image references. Both the version tag and the multi-platform manifest digest are required so a tag change cannot silently replace the runtime.

| Component | Image |
| --- | --- |
| Peer | `hyperledger/fabric-peer:2.5.16@sha256:09ee75042de9983bfde31ca88a5bf033386351f10a990e4c48264ee50172dee0` |
| Orderer | `hyperledger/fabric-orderer:2.5.16@sha256:e322c57331d37e0a35ffae3cb3d3265a0e852211c0f801f2514cc15b964ffc93` |
| Administrative tools | `hyperledger/fabric-tools:2.5.16@sha256:1d163b2513453637c2eb8ffe00bfb367f6edb2fb824604818f30646f552c9f42` |
| Fabric CA | `hyperledger/fabric-ca:1.5.17@sha256:fac0c4a70afc2fe6ae291ffb3c6d27db87ac638ecf5b5418841c7363588e568a` |

`.env.example` is the reviewed source for those references. `npm run infra:init` copies newly introduced settings to the ignored `.env` without replacing existing credentials. The network definition verifier fails if a reference loses its digest, no longer matches the selected Fabric patch or is not consumed by Compose.

## Identity boundary

The four MSPs have four separate Fabric CAs:

| Fabric CA | MSP | Issued identities |
| --- | --- | --- |
| `ca-orderer` | `TenantTrustOrdererMSP` | Orderer node and orderer organization administrator |
| `ca-platform` | `PlatformAuditMSP` | Platform peer, organization administrator, audit writer, verifier and commit listener |
| `ca-alpha` | `TenantAlphaAuditMSP` | Alpha peer, organization administrator and tenant auditor |
| `ca-beta` | `TenantBetaAuditMSP` | Beta peer, organization administrator and tenant auditor |

All enrollment and TLS keys, certificates, MSP directories and channel blocks are generated under ignored `runtime/fabric`. Fabric services do not mount `runtime/pki`, step-ca state or SaaS client certificate material. They also do not receive the Docker socket. The `tenantTrust.role` attribute is embedded into the least-privilege client enrollment certificates for use by the later chaincode task. Organization administrator identities are separate from application clients.

The Fabric CAs use TLS even on the private Compose network. Host ports bind to `127.0.0.1`; they are available for local inspection but not exposed to the LAN. The peer and orderer ledgers use project-specific Docker named volumes, while generated identity material stays in ignored runtime storage. Normal shutdown preserves both.

## Channel creation

The orderer uses the channel participation API and no system channel. `configtxgen` creates one application-channel genesis block per tenant from `infra/fabric/configtx.yaml`; `osnadmin` joins the orderer, then each peer joins only its intended channel.

| Node | Joined channels |
| --- | --- |
| Platform peer | `tt-audit-alpha-v1`, `tt-audit-beta-v1` |
| Tenant Alpha peer | `tt-audit-alpha-v1` |
| Tenant Beta peer | `tt-audit-beta-v1` |
| Orderer | Both channels |

The channel profiles include only the platform and matching tenant MSP. Application administration and default majority endorsement therefore require both application organizations on a two-organization channel. T8.4 will add the explicit chaincode endorsement and function-level role checks. T8.2 does not deploy chaincode, write a commitment or claim application-level audit behavior.

## Commands

Start or converge the network:

```text
npm run fabric:up
```

The command checks the committed topology and runtime definition, synchronizes missing `.env` settings, starts the four CAs, enrolls identities once, starts the nodes, creates and joins missing channels, then runs the live verification gate. Repeating the command preserves enrolled identities, channel blocks and ledger state and rechecks the same membership.

Verify the running network without changing it:

```text
npm run fabric:verify
```

Inspect service state:

```text
npm run fabric:status
```

Stop the network without deleting local identities or ledgers:

```text
npm run fabric:down
```

No automated reset command is provided because resetting the Fabric CA state, local identities and ledgers is destructive and must be an explicit operator decision.

## Verification boundary

`npm run fabric:verify` checks the reviewed image pins, service inventory, absence of SaaS PKI mounts and Docker socket access, ignored generated material, topology contract, live node reachability, exact peer channel membership, both orderer channels, four distinct CA roots and the five client role attributes. A successful pass establishes network bootstrap and tenant channel separation. It does not establish chaincode correctness, commitment privacy, delivery reliability or outage reconciliation; those belong to later Phase 8 tasks.

The established Fabric environment profile requires at least 5.5 GiB available to Docker for combined core-plus-Fabric work. An isolated network can be attempted with less and reports a warning, but the resource preflight remains failed until WSL/Docker exposes at least 5.5 GiB. Follow the existing local-development procedure and start with a 6 GB WSL allocation before integration work.

## References

- [Using the Fabric test network](https://hyperledger-fabric.readthedocs.io/en/release-2.5/test_network.html)
- [Creating a channel with the channel participation API](https://hyperledger-fabric.readthedocs.io/en/release-2.5/create_channel/create_channel_test_net.html)
- [Fabric CA users guide](https://hyperledger-fabric-ca.readthedocs.io/en/latest/users-guide.html)
