# Reproducible evaluation protocol and labels

## Status and purpose

T10.5 pre-registers the comparison protocol before any benchmark result is produced. The protocol status is `pre-registered-not-yet-executed`. T10.6 will implement the runner, and later tasks will execute and report the measurements without changing the labels or sample plan.

All modes consume `tenant-trust-comparison-workload-v1` from `@tenant-trust/evaluation`:

- Baseline A: signed JWT plus RBAC;
- Baseline B: tenant-scoped X.509 PKI plus RBAC; and
- Proposed framework: tenant-scoped X.509 PKI, adaptive trust and OPA.

The shared catalog has two tenants, four subjects, nine resources, five canonical actions and 14 authorization cases. A mode cannot replace a case with a mode-specific equivalent.

## Calibration and evaluation separation

The calibration partition contains five scenario families and 20 deterministic instances per family. It may select trust weights, decision bands, smoothing, hysteresis, source influence and critical corroboration rules. At most 12 candidate configurations may be compared. Calibration seeds start at 20261027 and derive from the scenario and instance indexes.

The evaluation partition uses different scenario IDs and seed namespaces. Calibration instances cannot be copied into evaluation. Before the first evaluation run, the runner must record a configuration hash covering trust settings, policy bundles, labels and scenario definitions. No weight, threshold, hysteresis rule, policy or label may change after that hash is sealed.

This separation prevents test scenarios from becoming tuning examples and preserves the slides' distinction between prototype defaults and calibrated values.

## Evaluation scenarios and ground truth

Ground truth is declared before execution. `legitimate-allow` means an `allow` is correct and every restriction is a false restriction. `unauthorized-restrict` means `step-up`, `deny` or `quarantine` can satisfy the scenario's declared outcomes, while `allow` is a missed restriction. `control-only` covers evidence, audit and recovery checks that do not have one access decision.

| Scenario ID | Class | Access truth | Required observation |
| --- | --- | --- | --- |
| `eval-normal-legitimate-access` | Benign | Legitimate allow | Shared normal workload remains available |
| `eval-unknown-device-sensitive-export` | Attack | Unauthorized restrict | Detect the context change and restrict export |
| `eval-failed-logins-sensitive-export` | Attack | Unauthorized restrict | Detect behaviour change and restrict export |
| `eval-certificate-and-evidence-replay` | Attack | Unauthorized restrict | Reject replay without changing trusted state |
| `eval-cross-tenant-access` | Attack | Unauthorized restrict | Deny before foreign data access and preserve the other tenant |
| `eval-evidence-flooding` | Attack | Control only | Bound source influence and preserve the other tenant's capacity |
| `eval-policy-version-change` | Resilience | Control only | Bind the decision to the active policy and fail closed on mismatch |
| `eval-off-chain-audit-record-modification` | Attack | Control only | Detect the modified record and causal-chain break |
| `eval-fabric-outage-and-recovery` | Resilience | Control only | Keep Fabric off the authorization path and reconcile pending commitments |
| `eval-corroborated-revocation-enforcement` | Attack | Unauthorized restrict | Revoke only after corroboration and deny subsequent certificate reuse |

A mode that lacks a required control receives `unsupported`. Unsupported controls remain visible and count as misses or failures in the relevant security denominator. They are never removed as not applicable merely because a baseline does not implement them.

## Sample plan and ordering

Each of the three modes runs at concurrency 1, 8 and 32. Every scenario/mode/load block has five warm-up repetitions followed by 30 measured repetitions. Warm-up results are excluded. Measured mode order rotates across repetitions to reduce fixed-order bias. Evaluation seeds start at 20261028 and derive from the scenario, load and repetition indexes.

The fixed plan produces:

- 2,700 measured scenario runs: 10 scenarios × 30 repetitions × 3 modes × 3 loads; and
- 3,780 measured shared-workload decisions: 14 cases × 30 repetitions × 3 modes × 3 loads.

Mode blocks run serially on one physical host, with a ten-second settle interval. A run must retain one row per observation with protocol ID, configuration hash, mode, scenario, workload case when applicable, concurrency, repetition, seed, start/end timestamps, observed outcome, reason and error status.

## Reference hardware and runtime

The reference host profile was captured before execution on 2026-10-28:

- AMD Ryzen 7 7840HS, 8 physical cores and 16 logical processors;
- 15.3 GiB visible memory;
- Samsung MZVL41T0HBLB-00BH1 SSD, 954 GiB;
- Microsoft Windows 11 Home Single Language, version 10.0.26200, build 26200;
- Node.js 24.20.0, npm 10.8.3 and Docker client 28.1.1; and
- Docker Desktop with WSL2.

Runs require AC power, local networking, no concurrent user workloads and serial mode blocks. The runner must capture the same non-private fields for every execution and report any mismatch. Host names, account names and hardware serial numbers are excluded.

## Metrics and denominators

Performance measurements report authentication, trust-computation, authorization and end-to-end latency in milliseconds using p50, p95, p99 and maximum. Throughput reports the median, minimum and maximum completed requests per second. Ledger commit delay and Fabric outage-recovery time are reported separately because ledger submission is asynchronous.

Security measurements have fixed denominators:

- attack-detection rate uses all attack trials with required controls;
- false-restriction rate uses all benign legitimate access trials;
- tenant-isolation rate uses all cross-tenant and isolation-stress trials;
- replay-rejection rate uses every certificate and evidence replay trial;
- audit-modification detection uses every off-chain tamper trial;
- ledger verification uses every expected commitment; and
- revocation-enforcement delay uses every corroborated revocation trial.

Timeouts and errors remain in security denominators and stay visible in latency results. Unsupported controls are reported separately and count as failures. Reports use two-sided bootstrap 95% confidence intervals with 10,000 resamples and seed 20261029, and retain raw observations so aggregates can be recomputed.

## Verified presentation citations

The protocol was checked against `Review2_Adaptive_Trust_Framework.pptx`, SHA-256 `68be85f2c8ca624f01cf978bc2b34aee2f6a7ba45a6ed01e51a628532ffb526d`, on 2026-10-28.

| Citation | Verified support |
| --- | --- |
| Slide 5 | Defines a synthetic, scenario-driven dataset and the two-tenant demonstration scope |
| Slide 6 | Lists normal, attack, tamper and outage scenarios and assigns sample counts to the evaluation-protocol task |
| Slide 9 | Labels trust weights and smoothing as uncalibrated design choices |
| Slide 10 | Labels trust bands as examples pending evaluation and defines the access outcomes |
| Slide 12 | Requires separate calibration/evaluation scenarios, the same workloads, increasing loads and repeated experiments |
| Slide 13 | Defines the performance, security, isolation, revocation and audit metrics and evaluation hypotheses |

The original Review 2 statements do not claim completed experiments. This document likewise defines the method without reporting results.

## Verification

Run:

```text
npm run evaluation-protocol:verify
```

The gate checks partition separation, closed labels, scenario coverage, exact sample counts, mode rotation, failure-denominator rules, reference hardware fields and the verified presentation revision and slide map.

