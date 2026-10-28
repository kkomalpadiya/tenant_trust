# Final release checklist

## Release contents

- [System architecture overview](architecture/system-overview.md)
- [API reference](api-reference.md)
- [Final demonstration script](demo-script.md)
- [Final project report](reports/final-project-report.md)
- [Effectiveness and isolation report](reports/effectiveness-and-isolation-evaluation.md)
- [Latency, throughput and recovery report](reports/latency-throughput-and-recovery-evaluation.md)
- [Ablation study and conclusions](reports/ablation-study-and-research-conclusions.md)
- `presentation/Tenant_Trust_Final_Demo.pptx`

## Fast package check

```text
npm run release-package:verify
```

This check verifies every release document and presentation, README links, the 100/100 dashboard state, the complete Phase 10 marker, all public API routes in the API reference, and absence of unresolved presentation placeholders in release text.

## Full release gate

```text
npm run release:verify
```

The full gate runs `foundation:clean` followed by the package check. The clean-foundation verifier creates an isolated temporary environment with unique ports, volumes and network names; initializes step-ca; starts PostgreSQL, Redis, NATS, step-ca and OPA; applies migrations; provisions demo identities; runs the complete repository regression and phase gates; performs the dependency audit; then removes only the isolated resources.

## Expected release state

- `git status --short` is empty before tagging or distribution.
- The review console reports 10/10 phases and 100/100 tasks.
- `npm test` reports 501 passing tests and no failures.
- The clean foundation reports `PASS clean foundation started, verified, and removed only its isolated resources.`
- The package check reports `PASS final release package is complete.`

The test count describes this release and should be updated when tests change.

## Operator notes

The full gate requires Docker Desktop with WSL2 and enough local resources for the core services. It creates immutable commitments in its isolated local Fabric and service state only where the invoked phase gates require them. Generated credentials, private keys, runtime databases and raw telemetry remain ignored and must not be committed.
