# Final demonstration script

## Goal and duration

This 12 to 15 minute demonstration shows the completed prototype without exposing private keys or production credentials. The review console uses deterministic synthetic state for presentation. The repository gates separately verify the infrastructure-heavy mTLS, certificate, OPA, Fabric and recovery paths.

## Presenter preparation

1. Install Node.js 24 LTS, npm, Docker Desktop with WSL2, Git and OpenSSL as described in [local development](local-development.md).
2. From the repository root, run `npm ci` after a fresh clone.
3. Run `npm run release-package:verify` for a fast package check.
4. For the full release proof, start Docker Desktop and run `npm run release:verify`. The command creates a disposable environment, verifies it and removes it.
5. Start the presentation console with `npm run demo:review` and open `http://127.0.0.1:4173`.

## Demonstration sequence

### 1. Frame the problem

Explain that a certificate proves identity at authentication time, while device, behavior, certificate and request risk can change afterward. The prototype keeps certificate validity and tenant isolation as mandatory gates, then adds current trust and request context.

### 2. Show tenant isolation

Select the Tenant Alpha member persona. Point out that the profile, certificate, trust explanation and history contain only that subject. Switch to the Tenant Alpha administrator and show same-tenant administrative visibility. Then run the cross-tenant review scenario and show the generic denial.

Expected result: the caller cannot select another tenant through headers, paths, query strings or request bodies.

### 3. Show certificate lifecycle

Open the certificate view. Show the tenant issuer, certificate state and lifecycle history. Use the synthetic issue or renew control, then revoke the certificate and rerun the protected-access scenario.

Expected result: revocation immediately prevents reuse in the review state. The real certificate lifecycle, two-issuer cryptography and status revalidation are covered by `npm run certificate-lifecycle:verify`.

### 4. Show explainable trust

Open the trust view. Identify the weighted identity, device, behavior, certificate and compliance components, the current smoothed score, freshness status, model version, configuration version and contributing evidence. Select an older transition to show its immutable explanation.

Expected result: the score is explainable and tenant-scoped. It remains one input to authorization, not an override for invalid identity or tenancy.

### 5. Show context-aware authorization

Open the access lab. Compare profile read, record read, sensitive export and tenant administration. Run the normal allow scenario, the suspicious sensitive-export scenario and the revoked-certificate scenario.

Expected result: OPA outcomes are `ALLOW`, `STEP_UP`, `DENY` or `QUARANTINE`, with bounded reason and policy provenance. A sensitive operation can require a bound single-use proof.

### 6. Show audit and recovery

Open Audit operations. Show pending and committed Fabric delivery, tenant channel placement, causal verification state and retryable operational failures. Explain that requests do not wait for Fabric. The durable outbox preserves work while a peer is unavailable.

Expected result: the dashboard exposes operational metadata without raw evidence or credentials. The measured recovery gate restored the peer and reconciled every pending commitment to zero gaps.

### 7. Present the evaluation results

Use the final slide deck in `docs/presentation/Tenant_Trust_Final_Demo.pptx`.

- Functional evaluation: 36,900 trials across all three modes. In the closed deterministic catalog, the adaptive mode achieved 100% attack detection, tenant isolation, replay rejection, audit modification detection and ledger verification, with 0% false restriction.
- Local performance: adaptive-mode p95 end-to-end decision latency stayed below 19 ms at registered loads 1, 8 and 32. Live OPA dominated the request time.
- Fabric: p95 commit delay was 2,190.359 ms and remained outside the request path. Three peer-outage repetitions preserved authorization and recovered without delivery gaps.
- Ablations: smoothing suppressed a single noisy restriction but delayed sustained restriction and recovery by one observation. Terminal feedback guards stopped recursive actions. A synchronous ledger model inflated p95 request time by 118.3x to 134.4x.

State the limits clearly: the scenarios are synthetic and closed, the host is single-machine, Baseline B starts after the trusted mTLS adapter result, and initial weights and thresholds are not calibrated on representative production data.

## Close

The demonstrated contribution is a reproducibly evaluated integration of tenant-bound identity, explainable adaptive trust, context-aware authorization, controlled certificate feedback and asynchronous verifiable audit commitments. It does not claim a new cryptographic primitive, trust algorithm, policy engine or ledger protocol.

Stop the console with `Ctrl+C`. If normal development infrastructure was started outside the disposable release gate, use `npm run infra:down`; do not delete volumes unless a deliberate reset is required.
