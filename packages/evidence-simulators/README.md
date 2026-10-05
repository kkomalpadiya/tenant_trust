# Deterministic evidence simulators

This package creates reproducible signed evidence fixtures for the five Phase 5 evidence types: identity, device, behaviour, certificate and compliance. The same tenant alias, subject, observation time and source sequence produce byte-for-byte identical envelopes, IDs, nonces, digests and Ed25519 signatures.

Each demo source derives a synthetic-only Ed25519 key from its tenant/source identity at runtime. The package exposes only the matching public enrollment record and signed envelopes; no private key is written to disk or returned. These derivable keys are test credentials and must never protect non-synthetic evidence.

Every envelope sets top-level `synthetic: true`. Device posture and compliance attestation objects also carry their own `synthetic: true` markers so downstream demonstrations cannot present those claims as measured production state.

Run `npm run evidence-simulators:verify` for the focused tests. Run `npm run evidence-simulators:generate -- --tenant alpha` to print the default Tenant Alpha fixture set, or add `--output <path>` to write JSON outside the repository.
