# Ablation study and research conclusions

## Scope

T10.9 compares the two baselines and the proposed framework using the completed T10.7 functional results and T10.8 live performance measurements. It then changes one design choice at a time for temporal smoothing, certificate-action feedback and Fabric placement.

The smoothing ablation executes the real trust implementation. The feedback ablation is bound to the implemented exactly-once and terminal-event policies, then uses a bounded counterfactual to show what would happen if terminal feedback could trigger another action. The ledger ablation combines the measured decision and commit distributions to model a synchronous critical-path variant. The unsafe feedback and synchronous-ledger variants are analysis models, not deployable configuration options or additional production measurements.

## Comparison of the three modes

Each mode has 12,300 measured functional trials in the closed deterministic catalog. Latency and throughput are the local single-host measurements from T10.8.

| Mode | Attack detection | False restriction | Tenant isolation | Replay rejection | Audit modification detection | Ledger verification |
|---|---:|---:|---:|---:|---:|---:|
| JWT + RBAC | 14.29% | 0.00% | 50.00% | 0.00% | 0.00% | 0.00% |
| PKI + RBAC | 14.29% | 0.00% | 50.00% | 0.00% | 0.00% | 0.00% |
| Adaptive trust + OPA | 100.00% | 0.00% | 100.00% | 100.00% | 100.00% | 100.00% |

| Mode | Load-1 p95 decision latency | Load-8 p95 | Load-32 p95 | Median throughput at loads 1 / 8 / 32 |
|---|---:|---:|---:|---:|
| JWT + RBAC | 0.111 ms | 0.135 ms | 0.147 ms | 10,488.463 / 8,340.114 / 8,265.458 requests/s |
| PKI + RBAC | 0.004 ms | 0.007 ms | 0.006 ms | 278,955.307 / 220,828.979 / 273,982.046 requests/s |
| Adaptive trust + OPA | 16.927 ms | 16.417 ms | 18.666 ms | 65.199 / 902.403 / 914.277 requests/s |

The proposed mode covers controls that the deliberately narrow baselines do not implement. Treating unsupported controls as failures explains its functional advantage in this catalog. This is a capability-scope comparison, not proof that adaptive trust will detect every real attack. The proposed mode also incurs the expected cost of schema validation, trust computation and live OPA evaluation. Baseline B starts from a trusted post-mTLS adapter result, so its in-process rate is not end-to-end TLS or HTTP throughput.

## Ablation 1: temporal smoothing

The implemented variant uses exponential smoothing with alpha 0.30. The counterfactual uses alpha 1.00, which makes every observation the complete current score. Both use the same initial score 75 and a restriction threshold of 60.

### One-sample low outlier

Input scores: `80, 80, 35, 80, 80`.

| Variant | Resulting score trace | Restricted samples | Threshold transitions |
|---|---|---:|---:|
| Configured smoothing | 76.50, 77.55, 64.79, 69.35, 72.54 | 0 | 0 |
| No smoothing | 80.00, 80.00, 35.00, 80.00, 80.00 | 1 | 2 |

For this fixed sequence, smoothing prevents a one-sample false restriction and two posture transitions.

### Sustained deterioration and recovery

Input scores: `80, 35, 35, 35, 35, 80, 80, 80, 80`.

| Variant | Low samples needed to restrict | Recovery samples needed to return to normal |
|---|---:|---:|
| Configured smoothing | 2 | 2 |
| No smoothing | 1 | 1 |

Smoothing reduces sensitivity to isolated noise, but delays both sustained-attack restriction and recovery by one observation in this sequence. This result supports retaining smoothing as a calibrated tradeoff. It does not validate alpha 0.30 as optimal.

## Ablation 2: certificate-action feedback

The implementation accepts at-least-once delivery but records exactly one trust effect. Certificate-revoked evidence has `securityActionEligible=false`, and the action-trigger policy lists it as a terminal non-trigger kind.

The experiment starts with one certificate action and three deliveries of its terminal lifecycle event. The unsafe counterfactual allows each terminal feedback effect to trigger another certificate action. Its observation is capped at five recursive generations so the analysis terminates.

| Variant | Durable trust effects | Additional action executions | Converged within the experiment |
|---|---:|---:|---:|
| Implemented non-recursive feedback | 1 | 0 | Yes |
| Terminal feedback action-eligible | 6 | 5 | No |

The implemented guard closes the causal chain after one durable effect. The counterfactual still produces another action at every observed generation. This supports the non-recursion rule as a safety control; the exact counterfactual counts are not a claim about real incident frequency.

## Ablation 3: Fabric placement

The implemented design authorizes first and submits audit commitments asynchronously. T10.8 measured a Fabric p95 commit delay of 2,190.359 ms separately from decision latency. The synchronous counterfactual adds that measured delay to the proposed mode's p95 decision latency.

| Load cap | Implemented asynchronous request p95 | Synchronous counterfactual p95 | Modeled inflation |
|---|---:|---:|---:|
| 1 | 16.927 ms | 2,207.286 ms | 130.4x |
| 8 | 16.417 ms | 2,206.776 ms | 134.4x |
| 32 | 18.666 ms | 2,209.025 ms | 118.3x |

The arithmetic counterfactual shows why Fabric should remain outside the request path. During the measured peer outage, the implemented design continued authorization and later reconciled the exact outbox event. A synchronous design would block or fail authorization with the ledger. The synchronous values are modeled sums of measured distributions, not a separate synchronized end-to-end benchmark.

## Research conclusions

1. Within the closed deterministic catalog, the integrated mode observes all required adaptive, isolation, replay, audit and ledger controls. The baselines correctly perform their narrower identity and RBAC functions but leave unsupported controls as measured failures.
2. The added controls have a measurable local cost. Proposed-mode p95 decision latency remains below 19 ms in this run, but it is much slower than either in-process baseline. Production latency and capacity remain unknown.
3. Temporal smoothing is not uniformly beneficial. It suppresses one-observation noise in the ablation and also delays restriction and recovery. Alpha and thresholds require calibration on representative labelled sequences.
4. Non-recursive terminal feedback is necessary for causal stability in this design. Exactly-once persistence prevents delivery replay, while action ineligibility prevents a new causal generation.
5. Asynchronous ledger commitment preserves the authorization availability boundary and avoids adding roughly 2.19 seconds of measured p95 commit delay to each request.

## Contribution and claim boundary

The demonstrated contribution is an implemented and reproducibly evaluated integration of established mechanisms: tenant-bound identity, deterministic explainable trust, OPA policy enforcement, controlled certificate feedback and asynchronous verifiable audit commitments.

This project does not claim:

- a novel cryptographic primitive, trust algorithm, policy engine or distributed-ledger protocol;
- effectiveness against attacks outside the closed deterministic scenario catalog;
- production performance, availability or service-level objectives;
- validated optimality of the initial weights, thresholds, smoothing alpha or recovery rules.

The results support engineering conclusions about this prototype. Establishing external validity would require representative labelled data, independent attack implementations, multi-host deployment, longer failure studies, parameter calibration and comparison with additional state-of-the-art systems.

## Reproduce

```text
npm run ablation-conclusions:verify
```

This gate runs the evaluation suite and verifies the frozen baseline comparison, real smoothing traces, implemented feedback controls, ledger counterfactual arithmetic and claim boundaries.
