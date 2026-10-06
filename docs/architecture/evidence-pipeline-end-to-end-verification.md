# Evidence pipeline end-to-end verification

Task T5.10 closes the signed-evidence phase with one deterministic integration gate. The gate composes the real ingestion, encryption, replay-protection, signed-event publication, event verification and consume-once APIs. Its test consumer models the downstream security-state boundary without introducing the Phase 6 trust engine.

## Verified path

The baseline fixture supplies all five required evidence types: identity, device, behaviour, certificate and compliance. Each signed envelope must:

1. authenticate against its tenant-scoped enrolled source key;
2. pass freshness, ordering, replay and source-safeguard checks;
3. be accepted with encrypted canonical evidence;
4. become a signed metadata-only `evidence.accepted.v1` event;
5. pass the consumer's tenant and producer-signature checks; and
6. produce one consume-once effect.

The test consumer stages verified events by tenant and subject. It commits one security-state revision only after all five evidence types are present. Publishing the same outbox claim again reuses the event ID and stream sequence, and redelivery does not repeat the effect or the security-state revision.

## Fail-closed path

The adversarial fixtures prove that forged signatures, revoked sources and mixed-tenant bindings never reach the stream. Duplicate event IDs are rejected after the first accepted occurrence. Flood protection admits only the configured bounded prefix, rate-limits the next events and suspends the noisy source. Partial evidence can be verified and staged, but missing behaviour or compliance evidence prevents a security-state revision.

The gate also tampers with an already signed accepted-evidence event. Consumer signature verification rejects it before the consume-once callback, leaving both the effect ledger and security state unchanged.

## Commands

Run the deterministic cross-package gate:

```powershell
npm run test:evidence-pipeline
```

Run the complete Phase 5 verification, including the existing live PostgreSQL and JetStream checks:

```powershell
npm run evidence-pipeline:verify
```

The deterministic gate is part of `npm test`. The complete verification command expects the local Docker foundation to be healthy and current migrations to be applied.
