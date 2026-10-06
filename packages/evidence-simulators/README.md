# Deterministic evidence simulators

This package creates reproducible signed evidence fixtures for the five Phase 5 evidence types: identity, device, behaviour, certificate and compliance. The same tenant alias, subject, observation time and source sequence produce byte-for-byte identical envelopes, IDs, nonces, digests and Ed25519 signatures.

Each demo source derives a synthetic-only Ed25519 key from its tenant/source identity at runtime. The package exposes only the matching public enrollment record and signed envelopes; no private key is written to disk or returned. These derivable keys are test credentials and must never protect non-synthetic evidence.

Every envelope sets top-level `synthetic: true`. Device posture and compliance attestation objects also carry their own `synthetic: true` markers so downstream demonstrations cannot present those claims as measured production state.

Run `npm run evidence-simulators:verify` for the focused tests. Run `npm run evidence-simulators:generate -- --tenant alpha` to print the default Tenant Alpha fixture set, or add `--output <path>` to write JSON outside the repository.

## Adversarial suite

`generateAdversarialEvidenceFixtureSet` creates six deterministic scenarios with explicit expected outcomes:

- a contract-valid envelope signed by an unregistered foreign key;
- a valid envelope whose source key has been revoked and source suspended;
- a valid signature that mixes one tenant's source with the other tenant's identity;
- a partial set missing behaviour and compliance signals;
- two independently signed observations that reuse one event ID; and
- an ordered seven-event burst with a four-event quota, two-strike automatic suspension and a 0.20 influence cap.

Every scenario contains only public enrollment data, synthetic envelopes, bounded safeguard settings and its rejection or withholding oracle. Generate it with `npm run evidence-simulators:generate -- --suite adversarial --tenant alpha`. Use `--flood-count` to increase the burst up to 1,000 events.
