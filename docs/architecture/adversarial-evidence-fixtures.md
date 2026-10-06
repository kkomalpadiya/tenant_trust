# Adversarial evidence fixtures

The deterministic evidence simulator owns a six-scenario adversarial suite for security and end-to-end verification. Every run with the same tenant, subject, observation time, sequence and flood count produces the same envelope identities, nonces, digests and signatures.

## Scenario boundaries

- `forged-signature` keeps the registered key ID and canonical digest but substitutes a signature from the other tenant's deterministic source key. The contract remains well formed while Ed25519 verification fails.
- `revoked-source` carries a valid signature together with suspended-source and revoked-key authority state. The ingestion resolver must return no trusted context.
- `mixed-tenants` signs an envelope that presents the other tenant and subject while retaining the originating tenant's source and key. The cryptography is valid, but no tenant-bound registry tuple exists.
- `missing-signals` contains valid identity, device and certificate evidence while explicitly omitting behaviour and compliance. Its oracle requires downstream trust processing to withhold state rather than treating absence as a safe value.
- `duplicate-event-id` contains two separately signed observations with different nonces, sequences and digests but the same event ID. The first may be accepted and the second must be rejected as a replay.
- `event-flood` sends seven ordered events against a four-event fixed-window quota. Two rate-limit failures trigger automatic source suspension, and the final event must fail because the verification context is no longer active.

Each scenario includes the minimum public enrollment records, synthetic envelopes, required authority or safeguard setup and an explicit expected outcome. Private keys remain runtime-derived test credentials and are never returned or written.

Run `npm run evidence-adversarial:verify` for fixture-shape tests plus ingestion-boundary execution of all six scenarios. The same generator can emit reviewable JSON with `npm run evidence-simulators:generate -- --suite adversarial --tenant alpha`.
