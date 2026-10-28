# Effectiveness and isolation evaluation

T10.7 applies `tenant-trust-effectiveness-isolation-report-v1` to the full measured portion of the pre-registered protocol. The deterministic reference evaluation contains 36,900 measured trials and 77,490 measured step observations: 12,300 trials per comparison mode across the same ten scenarios, concurrency levels and repetitions.

This is a functional reference evaluation of the implemented capability boundaries. It is not production traffic and does not estimate real-world attack prevalence. Unsupported controls remain in denominators as failures, exactly as pre-registered. T10.8 separately owns latency, throughput, resource use, ledger commit delay and outage-recovery performance.

## Rate outcomes

All rates show numerator/denominator followed by the two-sided 95% cluster-bootstrap interval. The bootstrap uses 10,000 resamples with registered seed base 20261029 and treats each scenario-mode-load-repetition run as one cluster, preserving correlation between concurrent lanes.

| Mode | Attack detection | False restriction | Tenant isolation | Replay rejection | Audit modification detection | Ledger verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| JWT + RBAC | 14.29% (1,230/8,610; 10.53–18.29%) | 0.00% (0/1,230; 0.00–0.00%) | 50.00% (1,230/2,460; 39.85–60.19%) | 0.00% (0/1,230; 0.00–0.00%) | 0.00% (0/1,230; 0.00–0.00%) | 0.00% (0/1,230; 0.00–0.00%) |
| PKI + RBAC | 14.29% (1,230/8,610; 10.61–18.30%) | 0.00% (0/1,230; 0.00–0.00%) | 50.00% (1,230/2,460; 39.96–60.04%) | 0.00% (0/1,230; 0.00–0.00%) | 0.00% (0/1,230; 0.00–0.00%) | 0.00% (0/1,230; 0.00–0.00%) |
| Adaptive trust + OPA | 100.00% (8,610/8,610; 100.00–100.00%) | 0.00% (0/1,230; 0.00–0.00%) | 100.00% (2,460/2,460; 100.00–100.00%) | 100.00% (1,230/1,230; 100.00–100.00%) | 100.00% (1,230/1,230; 100.00–100.00%) | 100.00% (1,230/1,230; 100.00–100.00%) |

Both baselines correctly rejected the direct cross-tenant access trials. Their 1,230 isolation failures are the evidence-flood isolation trials whose source-influence and neighboring-tenant capacity controls are outside those baseline definitions. Their attack-detection numerator therefore contains the 1,230 cross-tenant trials only. The proposed mode observed every required control and restriction in this closed deterministic catalog. Perfect functional results do not establish performance or effectiveness on unrepresented attacks.

## Revocation enforcement

| Mode | Successful/denominator | Unbounded failures | Median | p95 | Median 95% interval |
| --- | ---: | ---: | ---: | ---: | ---: |
| JWT + RBAC | 0/1,230 | 1,230 | Not available | Not available | Not available |
| PKI + RBAC | 0/1,230 | 1,230 | Not available | Not available | Not available |
| Adaptive trust + OPA | 1,230/1,230 | 0 | 274 ms | 313 ms | 270–277 ms |

An unbounded failure means the mode did not complete the full path from corroborated critical evidence to denial of certificate reuse. JWT + RBAC is not certificate-bound, while PKI + RBAC rejects an already revoked certificate but does not initiate evidence-driven revocation. The proposed-mode times use the deterministic scenario clock and measure functional enforcement ordering; they are not wall-clock service latency.

## Reproduction and interpretation

The analyzer rejects verification-only or incomplete workloads. It requires all three modes and exactly 1,230 measured trials per scenario and mode. It groups raw observations by mode, run and concurrent lane, checks every pre-registered required control, verifies restrictive authorization outcomes where applicable, and retains unsupported, error and timeout observations in denominators.

Run the complete gate with:

```text
npm run effectiveness-isolation:verify
```
