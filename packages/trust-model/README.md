# Normalized trust model definition

`@tenant-trust/trust-model` defines the shared Phase 6 trust-component vocabulary and initial weight configuration. Every component is a finite number from 0 to 100, where a larger value represents a more trusted posture. A component vector is valid only when identity, device, behaviour, certificate and compliance are all present exactly once.

The initial model version is `1.0.0`. Its uncalibrated defaults are 0.20 identity, 0.25 device, 0.25 behaviour, 0.15 certificate and 0.15 compliance. `defineTrustModelConfiguration` accepts a complete tenant-tuned alternative only when every weight is between 0 and 1 and the five weights sum to 1. It returns a new immutable configuration and never mutates the defaults.

This package validates normalized inputs and configuration only. It does not translate raw evidence into component values, calculate a weighted score, smooth observations, persist trust state or authorize a request. Missing evidence is not converted to zero. A trust component also cannot make an invalid, revoked or foreign-tenant credential acceptable.

Run `npm run trust-model:verify` from the repository root.
