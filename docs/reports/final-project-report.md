# Final project report

## Executive summary

Tenant Trust implements and evaluates an adaptive security framework for a two-tenant SaaS prototype. The system binds identity to tenant-specific X.509 certificates, validates signed security evidence, computes explainable trust state, applies context-aware OPA decisions, executes controlled certificate actions and records asynchronous commitments on tenant-separated Hyperledger Fabric channels.

All ten phases and 100 tracked tasks are complete. The final release includes a clean-start gate, 501-test regression suite, tenant-scoped review console, API and architecture documentation, demonstration script, updated presentation and reproducible evaluation reports.

## Research problem

Static authentication and role checks do not capture risk that changes after login. A valid certificate can coexist with a newly unknown device, suspicious behavior, stale security state or a sensitive request. Multi-tenant systems also need to prevent trust or certificate data from one tenant influencing another.

The project asks whether an integrated prototype can retain strict certificate and tenant boundaries while adding current, explainable trust and auditable feedback. It compares the integrated mode against JWT plus RBAC and tenant-scoped PKI plus RBAC on the same synthetic workload catalog.

## Implemented system

The prototype contains these completed boundaries:

- tenant and subject authority derived from trusted certificate and database state;
- tenant-specific certificate issuers with issue, renewal, status and permanent revocation controls;
- signed Ed25519 evidence with source enrollment, freshness, ordering, replay and size safeguards;
- encrypted tenant-scoped off-chain evidence storage and bounded event delivery;
- deterministic weighted trust with temporal smoothing, freshness, versions and durable explanations;
- role, ownership, sensitivity, trust and request-context authorization through OPA;
- bound single-use step-up proofs for sensitive operations;
- idempotent restriction, quarantine, revocation and governed recovery with non-recursive feedback;
- canonical audit commitments, durable asynchronous delivery and causal verification against Fabric;
- tenant-scoped certificate, trust, decision and audit-operations dashboards.

The [system overview](../architecture/system-overview.md) maps these components and their failure behavior. The [API reference](../api-reference.md) documents the protected SaaS, step-up and evidence routes.

## Evaluation design

The pre-registered protocol fixes ten scenarios, three modes, three load caps and separate calibration and evaluation partitions. Unsupported controls remain failures in metric denominators. Functional uncertainty uses 10,000 cluster-bootstrap resamples. Performance uses a live single-host run with real OPA evaluation and separate real Fabric commits. The workload and analysis reject incomplete or verification-only runs.

The scenarios cover normal access, unknown device, suspicious behavior before export, certificate and evidence replay, cross-tenant access, evidence flooding, policy change, off-chain audit modification, Fabric outage and corroborated revocation.

## Functional results

The functional run contains 36,900 measured trials and 77,490 step observations, with 12,300 trials per mode.

| Mode | Attack detection | False restriction | Tenant isolation | Replay rejection | Audit modification detection | Ledger verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| JWT + RBAC | 14.29% | 0.00% | 50.00% | 0.00% | 0.00% | 0.00% |
| PKI + RBAC | 14.29% | 0.00% | 50.00% | 0.00% | 0.00% | 0.00% |
| Adaptive trust + OPA | 100.00% | 0.00% | 100.00% | 100.00% | 100.00% | 100.00% |

The baselines correctly reject direct cross-tenant access. Their isolation failures come from evidence-flood influence and neighboring-tenant capacity controls that the baseline definitions do not implement. The integrated mode completed evidence-driven revocation in all 1,230 trials with a deterministic scenario-clock median of 274 ms. These functional timings are not wall-clock service latency.

## Performance and recovery results

The live reference run measured 3,780 decisions. Adaptive-mode p95 end-to-end latency was 16.927 ms at load 1, 16.417 ms at load 8 and 18.666 ms at load 32. Median throughput increased from 65.199 requests/s at load 1 to 902.403 and 914.277 requests/s at loads 8 and 32. Live OPA evaluation dominated the request time.

Baseline A performed real Ed25519 JWT verification. Baseline B began after a trusted mTLS adapter result, so its very high in-process rate is not TLS or HTTP throughput.

Thirty real Fabric submissions produced a 2,170.608 ms median and 2,190.359 ms p95 commit delay. That delay remained outside the request path. Three real peer outages preserved authorization, recovered in a median 9,365.072 ms and reconciled the exact pending events to zero delivery gaps.

## Ablation findings

With alpha 0.30, smoothing prevented a restriction from one low outlier. On the fixed sustained-deterioration sequence, it delayed both restriction and recovery by one observation compared with alpha 1.00. This supports smoothing as a tradeoff, not as an optimal calibrated setting.

The implemented terminal-feedback rule recorded one trust effect from repeated certificate lifecycle delivery and triggered no new action. A bounded unsafe counterfactual produced another action at every observed generation.

Keeping Fabric asynchronous avoided adding its measured p95 delay to every decision. The synchronous counterfactual produced modeled p95 request times of 2,206.776 to 2,209.025 ms, or 118.3x to 134.4x the implemented request path.

## Contribution and limits

The contribution is an implemented and reproducibly evaluated integration of established mechanisms. The results show how tenant-bound identity, explainable adaptive trust, OPA enforcement, controlled certificate feedback and asynchronous ledger commitments behave together in this prototype.

The project does not establish effectiveness against attacks outside the closed deterministic catalog, production performance, multi-host availability or optimal weights and thresholds. Device and compliance signals are synthetic. External validation requires representative labeled data, independent attack implementations, longer failure studies, parameter calibration and additional comparison systems.

## Reproduction and release

Run `npm run release-package:verify` for the fast artifact check. Run `npm run release:verify` with Docker Desktop available for the disposable clean start, complete foundation verification and final package check. The detailed presenter sequence is in the [demo script](../demo-script.md), and the complete release inventory is in the [release checklist](../release-checklist.md).

Supporting reports:

- [Effectiveness and isolation evaluation](effectiveness-and-isolation-evaluation.md)
- [Latency, throughput and recovery evaluation](latency-throughput-and-recovery-evaluation.md)
- [Ablation study and research conclusions](ablation-study-and-research-conclusions.md)
