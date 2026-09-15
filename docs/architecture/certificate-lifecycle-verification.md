# Complete certificate lifecycle verification

## Gate

`npm run certificate-lifecycle:verify` is the Phase 3 completion gate. It runs the repository tests once, then executes the tenant CA definition, real certificate issuance, PostgreSQL inventory, renewal, live revocation, transactional event outbox, signed JetStream delivery, encrypted CA recovery and end-to-end certificate-boundary checks in a fail-fast order.

The foundation verifier invokes the same gate with `--skip-unit-tests` because it has already run the repository test suite. This keeps one authoritative Phase 3 sequence without duplicating the unit run.

## End-to-end scenario

The boundary verifier creates an ephemeral platform root, isolated Alpha and Beta intermediates, and an untrusted root with a look-alike Alpha issuer name. All generated private keys stay under ignored `runtime/` storage and are removed in a `finally` cleanup.

| Scenario | Expected result | Boundary proved |
| --- | --- | --- |
| Alpha leaf signed by the selected Alpha intermediate | Accept while authoritative inventory state is fresh and active | Exact tenant, subject, issuer, serial, fingerprint and validity binding |
| Alpha request signed by the valid Beta intermediate under the same platform root | Reject | A trusted root is insufficient; tenant issuer selection remains exact |
| Alpha request signed by a look-alike intermediate under an untrusted root | Reject | Matching issuer text cannot replace signature verification against the selected issuer key |
| Valid Alpha certificate presented with Beta authenticated context | Reject before status lookup | Certificate identity cannot switch the trusted tenant |
| Eligible Alpha renewal with a new CSR key | Accept successor and deny predecessor as superseded | Fresh-key rotation and atomic lifecycle state transition |
| Issuer-confirmed successor revocation | Deny permanently and do not cache an allow | Revoked inventory state overrides otherwise valid X.509 material |
| Correctly signed Alpha certificate whose X.509 validity has ended | Reject before status lookup | Expiry is enforced locally and cannot be hidden by stale inventory |

The earlier gates in the same command add persistent and transport coverage that the in-memory boundary scenario does not duplicate: PostgreSQL constraints and row-level security, live Smallstep revocation, causal outbox records, Ed25519 source authentication, JetStream acknowledgement ordering and encrypted CA backup/restore.

## Scope

Passing this gate establishes the implemented local Phase 3 behavior. It does not claim production HSM custody, deployed long-running per-tenant CA services, gateway mTLS enforcement or protection against a compromised development host. T4.1 applies the verified certificate identity at the API boundary.

