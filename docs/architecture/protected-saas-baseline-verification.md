# Protected SaaS baseline verification

## Phase 4 gate

`npm run protected-saas:verify` is the fail-fast completion gate for the certificate-authenticated SaaS baseline. It runs the repository tests and then composes the independently implemented Phase 4 boundaries in a fixed order. It creates no new authorization path and does not replace the narrower diagnostic commands.

| Required outcome | Verification evidence |
| --- | --- |
| Allowed actions | The live profile and record scenario accepts the authenticated member's profile and owned record, permits the tenant administrator's tenant-wide record reads, and exercises explicitly authorized sensitive demonstration operations. |
| Role denial | The authorization matrix exhaustively checks each role/action row. The live sensitive-operation scenario denies tenant members and denies missing internal controls before data queries. |
| Cross-tenant denial | Alpha cannot read Beta records, export a mixed Alpha/Beta batch or review a Beta membership. Forged tenant and subject headers do not change the authenticated context, and invisible local/foreign identifiers share one denial. |
| Certificate revocation | One reused API identity and PostgreSQL backend accepts the active certificate, then rejects it on the next request after authoritative inventory state changes to revoked. |
| Spoofing and direct bypass | A disposable real NGINX and TLS receiver accept the valid tenant chain while rejecting a missing client certificate, forged identity headers, a wrong-tenant issuer, unauthenticated direct access and an internal-CA-valid certificate that is not the pinned gateway. |

The gate also reruns request-outcome capture and session, timeout, body-size and replay safeguards. Schema checks prove the runtime roles retain only constrained writer/reservation access. Live verification data is rolled back or explicitly removed, and the gateway verifier removes its container and generated private keys in cleanup.

## Scope

Passing this command completes the implemented Phase 4 Baseline B boundary: mTLS identity, current certificate and tenant state, role/resource authorization, forced tenant isolation, sensitive-operation controls, sanitized audit and request safeguards. It does not claim adaptive trust or OPA authorization, browser session support, production network isolation, or Fabric audit commitment. Those remain later phases.
