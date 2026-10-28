# Evaluation baselines

`@tenant-trust/evaluation` owns the fixed comparison scope and the evaluation-only JWT plus RBAC implementation used by Baseline A.

All three comparison modes reference `tenant-trust-comparison-workload-v1`. The catalog contains the same two tenants, four subjects, resource identifiers, five canonical actions and Alpha/Beta isolation probes. Future protocol and workload-runner tasks must consume this catalog rather than creating mode-specific scenarios.

Baseline A accepts only compact EdDSA JWTs with an exact `typ`, `alg` and `kid`. The signed claims bind issuer, audience, token ID, tenant, subject, roles and a maximum five-minute validity window. The verifier rejects noncanonical encoding, unknown fields, tampering, wrong keys, future tokens and expiry. After verification, it resolves a branded `trusted-session` tenant context against current tenant, subject and membership state, then applies the existing `role-action-matrix-v1` and explicit resource scope.

This is deliberately a JWT plus RBAC comparator: an eligible tenant administrator can perform export or tenant administration based on the signed role and tenant scope alone. It does not use adaptive trust, certificates, OPA, step-up or Fabric audit. Signed roles remain valid until token expiry, although tenant, subject and membership suspension is checked for every evaluation call. No HTTP route or production API authentication path accepts these tokens.

`tenant-trust-evaluation-protocol-v1` pre-registers the separate calibration and evaluation partitions, ten evaluation scenarios, closed ground-truth labels, exact sample counts, concurrency levels, mode rotation, reference hardware, metric denominators and source-slide map. Unsupported baseline controls stay visible and count as security misses rather than disappearing from denominators. The protocol defines the future experiment; it does not contain benchmark results.

`tenant-trust-workload-runner-v1` converts those scenarios into ordered benign, attack and resilience steps. The full plan derives all 3,150 warm-up plus measured scenario runs from the frozen protocol, launches the requested concurrent lanes and retains one labelled observation per step. A separate verification-only profile checks all scenarios and modes without producing benchmark data.

`tenant-trust-effectiveness-isolation-report-v1` accepts only complete full-protocol output. It reports attack detection, false restriction, tenant isolation, replay rejection, audit modification detection, ledger verification and revocation enforcement with explicit numerators, denominators, unsupported failures and deterministic 95% cluster-bootstrap intervals. Reference adapters model the verified functional capability boundary; performance and real-world prevalence claims remain out of scope.

`tenant-trust-performance-recovery-report-v1` validates all nine registered mode/load blocks and summarizes authentication, trust, authorization and end-to-end latency without mixing in Fabric commit delay. The live runner uses the shared 14-case workload for 3,780 measured decisions, records Node.js CPU/RSS and throughput, submits 30 measured commitments, and exercises three real peer outage/recovery cycles. See [`docs/reports/latency-throughput-and-recovery-evaluation.md`](../../docs/reports/latency-throughput-and-recovery-evaluation.md).

`tenant-trust-ablation-study-v1` freezes the measured baseline/proposed comparison and executes three controlled variants. Real temporal scoring compares alpha 0.30 with no smoothing, the feedback counterfactual tests the consequence of making terminal lifecycle evidence action-eligible, and the ledger counterfactual places measured Fabric commit delay on the request path. The conclusion boundary describes the contribution as an evaluated integration and explicitly excludes unsupported novelty, generalization and production claims. See [`docs/reports/ablation-study-and-research-conclusions.md`](../../docs/reports/ablation-study-and-research-conclusions.md).

Run the focused gate with:

```text
npm run jwt-rbac-baseline:verify
npm run evaluation-protocol:verify
npm run workload-runner:verify
npm run effectiveness-isolation:verify
npm run performance-recovery:verify
npm run ablation-conclusions:verify
```
