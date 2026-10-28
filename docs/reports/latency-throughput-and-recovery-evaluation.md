# Latency, throughput and recovery evaluation

## Result

T10.8 is complete on the registered single-host reference environment. The live run measured 3,780 authorization decisions across all three comparison modes and concurrency caps 1, 8 and 32, plus 30 measured Fabric commitments and three reversible Alpha-peer outage/recovery repetitions. Ledger work remained outside the request decision path.

These are local prototype measurements, not production service-level objectives. Baseline B is intentionally an in-process comparator and its authentication stage begins after the reverse proxy has established a trusted mTLS adapter result; it does not include a TLS handshake or certificate-chain verification.

## Method

- Workload: the same 14 cases in `tenant-trust-comparison-workload-v1` for every mode.
- Decision samples: 5 warm-up and 30 measured workload repetitions for each mode/load block, giving 420 measured decisions per block and 3,780 total.
- Load: concurrency caps 1, 8 and 32. A replay has 14 cases, so the last cap schedules at most 14 simultaneous requests.
- Stage clock: monotonic `process.hrtime.bigint()` around authentication, trust computation, authorization and complete decision processing.
- Proposed framework: real weighted trust computation, input-contract validation, loopback HTTP and live OPA evaluation.
- Ledger: 5 warm-up and 30 measured real Gateway submissions; delay starts before submit and ends after successful commit status.
- Recovery: three real peer stops. Authorization was verified while the peer was down; recovery timing starts at the peer restart command and ends after health, retry and exact ledger commitment.
- Resources: CPU and RSS cover the Node.js measurement process. Container CPU/RSS for OPA, Docker and Fabric are excluded.

The runner rotates mode order by load, uses the registered reference-host profile, validates complete mode/load coverage and emits a machine-readable JSON report to standard output.

## Decision latency and throughput

All latency values are milliseconds. Throughput is requests per second. `—` means the mode has no adaptive trust stage; it is not a zero-duration observation.

| Mode | Load cap | Auth p50 / p95 / max | Trust p50 / p95 / max | Authorization p50 / p95 / max | End-to-end p50 / p95 / max | Throughput median / min / max |
|---|---:|---:|---:|---:|---:|---:|
| JWT + RBAC | 1 | 0.088 / 0.104 / 0.177 | — | 0.004 / 0.006 / 0.029 | 0.092 / 0.111 / 0.196 | 10,488.463 / 9,296.766 / 11,037.528 |
| PKI + RBAC | 1 | 0.002 / 0.003 / 0.030 | — | 0.001 / 0.001 / 0.026 | 0.003 / 0.004 / 0.031 | 278,955.307 / 177,890.724 / 299,145.299 |
| Adaptive trust + OPA | 1 | 0.020 / 0.030 / 0.056 | 0.030 / 0.047 / 0.094 | 15.439 / 16.884 / 24.853 | 15.488 / 16.927 / 24.903 | 65.199 / 61.690 / 78.724 |
| JWT + RBAC | 8 | 0.112 / 0.129 / 0.215 | — | 0.004 / 0.007 / 0.029 | 0.116 / 0.135 / 0.230 | 8,340.114 / 7,439.290 / 8,632.916 |
| PKI + RBAC | 8 | 0.003 / 0.005 / 0.026 | — | 0.001 / 0.002 / 0.039 | 0.004 / 0.007 / 0.042 | 220,828.979 / 91,383.812 / 238,907.850 |
| Adaptive trust + OPA | 8 | 0.011 / 0.024 / 0.039 | 0.018 / 0.035 / 0.085 | 7.366 / 16.389 / 20.785 | 7.398 / 16.417 / 20.809 | 902.403 / 585.840 / 1,451.033 |
| JWT + RBAC | 32 | 0.112 / 0.140 / 0.191 | — | 0.004 / 0.008 / 0.016 | 0.116 / 0.147 / 0.201 | 8,265.458 / 6,603.462 / 9,785.420 |
| PKI + RBAC | 32 | 0.002 / 0.004 / 0.044 | — | 0.001 / 0.001 / 0.002 | 0.003 / 0.006 / 0.046 | 273,982.046 / 109,289.617 / 290,456.432 |
| Adaptive trust + OPA | 32 | 0.009 / 0.023 / 0.051 | 0.015 / 0.032 / 0.070 | 12.444 / 18.644 / 22.308 | 12.468 / 18.666 / 22.326 | 914.277 / 608.204 / 1,628.305 |

The in-process PKI comparator's very high rate reflects its narrow scope and must not be interpreted as HTTP or TLS throughput. For the proposed framework, the live OPA round trip dominates end-to-end latency. Concurrency raises median throughput from 65.199 requests/s at load 1 to 902.403 at load 8 and 914.277 at load 32, while p95 end-to-end latency remains below 19 ms in the concurrent blocks.

## Node.js process resources

| Mode | Load cap | CPU ms / decision | RSS start MiB | RSS end MiB | RSS peak MiB |
|---|---:|---:|---:|---:|---:|
| JWT + RBAC | 1 | 0.111905 | 100.324 | 101.043 | 101.043 |
| PKI + RBAC | 1 | 0.000000 | 101.375 | 101.570 | 101.570 |
| Adaptive trust + OPA | 1 | 1.673810 | 108.992 | 128.820 | 128.820 |
| JWT + RBAC | 8 | 0.111905 | 134.141 | 136.504 | 136.504 |
| PKI + RBAC | 8 | 0.000000 | 128.820 | 128.895 | 128.895 |
| Adaptive trust + OPA | 8 | 1.154762 | 128.668 | 133.727 | 135.195 |
| JWT + RBAC | 32 | 0.147619 | 138.590 | 138.918 | 138.918 |
| PKI + RBAC | 32 | 0.000000 | 139.035 | 139.316 | 139.316 |
| Adaptive trust + OPA | 32 | 0.707143 | 138.430 | 138.289 | 141.445 |

CPU observations are integer microsecond deltas. The PKI-only blocks completed below that clock's useful aggregate resolution and therefore report `0.000000`; they are not evidence of zero computational cost. RSS is process-wide and carries allocation from earlier rotated blocks, so it is useful as a run envelope rather than isolated per-mode memory ownership.

## Ledger commit delay and outage recovery

| Metric | Samples | p50 / median | p95 | p99 | max |
|---|---:|---:|---:|---:|---:|
| Fabric ledger commit delay (ms) | 30 | 2,170.608 | 2,190.359 | 2,193.132 | 2,193.452 |
| Fabric outage recovery time (ms) | 3 | 9,365.072 | — | — | 9,406.098 |

The commit-delay distribution is deliberately separate from the request latency table. The application can finish authorization while Fabric is unavailable because commitments use the durable outbox. In every recovery repetition the same pending event was retried after the Alpha peer became healthy, its exact ledger value was verified, the delivery report returned to zero gaps, and the peer was left healthy.

## Reproduce

With the core services and Fabric network healthy:

```text
npm run performance-recovery:verify
```

The command first runs the evaluation unit tests, then prints the complete JSON measurement record. It creates immutable test commitments in the local Fabric ledger. Temporary PostgreSQL recovery rows are deleted after each repetition; ledger commitments remain by design.

## Interpretation boundaries

- The fixed workload and local host make modes comparable within this run, but they do not model internet latency, production ingress, multi-host Fabric or realistic user think time.
- Baseline A measures real Ed25519 JWT verification. Baseline B starts from a trusted post-mTLS adapter result. The proposed mode starts from the same trusted adapter result and adds weighted trust plus live OPA.
- The decision run measures performance, not security effectiveness; T10.7 owns effectiveness and isolation outcomes.
- Initial weights and policy thresholds remain unvalidated prototype defaults.
