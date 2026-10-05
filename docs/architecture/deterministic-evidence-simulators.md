# Deterministic evidence simulators

## Purpose and boundary

`@tenant-trust/evidence-simulators` generates signed synthetic inputs for Phase 5 development and verification. One fixture set contains identity, device, behaviour, certificate and compliance observations for either deterministic demo tenant. It produces source-side input only: it does not enroll keys, accept evidence, persist raw payloads, enforce replay rules or calculate trust.

The simulator defaults match the source IDs and freshness limits provisioned in `database/seeds/003_demo_security_configuration.sql`. Tenant Alpha defaults to Alice; Tenant Beta defaults to Bob. A caller may select the demo tenant, subject, exact UTC observation time and non-negative source sequence. It cannot replace the source catalog, evidence type, source freshness limit or payload shape through the fixture-set API.

## Reproducibility

The generator uses length-prefixed inputs and SHA-256 domain labels to derive each synthetic source's Ed25519 seed, opaque version-8 `key_UUID`, version-8 `eventId` and 18-byte nonce. UUID variant/version bits are normalized before formatting. Ed25519 signatures are deterministic, so identical inputs reproduce the complete fixture byte surface. Changing the tenant, source, subject, observation time, sequence or payload changes the derived event identity and signature.

These derivable keys are intentionally public test credentials. They must never authenticate real evidence. The package retains private key objects only inside a simulator closure, never returns them and never writes them to disk. It exposes a public enrollment record containing the tenant, source, evidence type, `keyId`, raw Ed25519 public key and its SHA-256 fingerprint so T5.2 enrollment and later ingestion tests can use the exact matching verifier.

## Signal shapes

Every envelope follows `signed-evidence-envelope.schema.json`, uses the `tenant-trust-evidence-json-v1` canonicalization profile, and sets top-level `synthetic: true` plus a synthetic provenance object.

| Evidence type | Deterministic baseline claim |
| --- | --- |
| Identity | Active directory identity with AAL2 password and TOTP factors. |
| Device | Managed, encrypted, locked and recently patched low-risk posture. The nested posture is explicitly synthetic. |
| Behaviour | No failed-login, impossible-travel or new-country indicator and a low risk band. |
| Certificate | Active application-inventory status with 30 days to expiry. |
| Compliance | Twelve of twelve demo controls passing. The nested attestation is explicitly synthetic. |

The fixtures are demonstrations, not assertions about a real person, device or compliance program. Later ingestion and trust tasks must preserve the synthetic marker and must not turn these claims into production posture.

## Verification and use

Run `npm run evidence-simulators:verify`. The gate compiles the signed-envelope schema, generates all five types twice, requires byte-for-byte equality, recomputes every canonical digest, verifies every Ed25519 signature, checks tenant separation and proves nested posture/compliance markers. Unit tests also cover tampering, input variation, malformed selectors and the absence of serialized private material.

Run `npm run evidence-simulators:generate -- --tenant alpha` to print a JSON fixture set. Optional arguments are `--tenant alpha|beta`, `--observed-at <RFC3339 UTC>`, `--sequence <safe integer>` and `--output <new path>`. Output creation refuses to overwrite an existing file.
