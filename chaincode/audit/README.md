# Tenant Trust audit chaincode

This TypeScript Fabric contract stores only the T8.3 public commitment value. `CommitCommitment` is restricted to the Platform audit writer, writes the commitment and its opaque event anchor atomically, returns `duplicate` without a write for an exact retry, and rejects conflicting state. `ReadCommitment` is restricted to the Platform verifier or the tenant auditor whose MSP belongs to the current tenant channel.

`npm run ledger-privacy:verify` exercises the deployed boundary with both tenant-auditor identities. It proves that each auditor can read only its own channel, the other tenant's key is absent from local state, rejected cross-channel queries return no commitment value, and successful state contains only the six approved public fields.

Run `npm test --workspace @tenant-trust/audit-chaincode` for the local contract tests. The root `npm run fabric-chaincode:verify` command builds the external-service image, deploys the definition to both tenant channels and exercises the live authorization and duplicate rules.
