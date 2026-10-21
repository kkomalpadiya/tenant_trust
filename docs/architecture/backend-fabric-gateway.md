# Backend Fabric Gateway integration

T8.5 adds a server-only Fabric Gateway boundary to the API workspace. It maps the authenticated application `tenantId` to the configured tenant channel in `config/fabric-topology.json`; neither an HTTP caller nor a method caller can provide a channel name. The boundary accepts only the six-field T8.3 ledger value for submission and the opaque record type plus event-key hash for queries.

## Identity separation

The backend opens two Fabric Gateway sessions over one TLS-authenticated gRPC connection to the Platform peer:

- `audit-writer@platform.audit.tenant-trust.test` signs `CommitCommitment` submissions.
- `audit-verifier@platform.audit.tenant-trust.test` evaluates `ReadCommitment` queries.

The chaincode retains the T8.4 authorization split, so neither identity gains the other operation. MSP certificates and private keys remain under ignored `runtime/fabric` paths. The connector reads them inside the backend process, clears the temporary private-key byte buffer after creating the signer and exposes only `submitCommitment`, `queryTransactionStatus`, `readCommitment`, `close` and non-secret policy metadata. The public Fastify application defines no ledger route and never reads a Fabric credential path.

## Configuration

Local defaults target `127.0.0.1:17051` with the TLS server name `peer0.platform.audit.tenant-trust.test`. Backend-only environment settings can override the endpoint, TLS root, writer/verifier MSP directories, topology file and bounded request timeout. Secret material is never copied into `.env` or committed.

Run `npm run fabric:up` before `npm run fabric-gateway:verify`. The verification command runs unit tests, checks the topology/network definition, connects through the official Node Fabric Gateway client, submits and reads a deterministic commitment on both tenant channels, waits for the validation result, reconciles the transaction through QSCC, proves exact retries are duplicates and rejects an unmapped tenant before any ledger call.
