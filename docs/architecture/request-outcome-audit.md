# Request outcome and correlation audit

## Boundary

Every schema-valid protected API request receives a server-generated `req_<UUID>` request ID and `cor_<UUID>` correlation ID before authentication. The API returns both as `X-Request-ID` and `X-Correlation-ID`, but never accepts either value from request headers. Authentication and access events for one request carry the same pair. A successful sensitive operation also carries the `op_<UUID>` created by the repository.

API construction requires the branded `append-only-request-outcomes-v1` recorder. A copied or missing recorder prevents startup. If authentication-event capture fails, the protected repository is not called. If an access outcome cannot be captured, the API returns `503 SERVICE_UNAVAILABLE` rather than releasing an unaudited successful result.

## Sanitized event fields

The recorder accepts an exact flat field set:

- event kind, request ID, correlation ID and observation time;
- trusted tenant and actor subject from the gateway authentication result;
- authentication source, server-defined action, HTTP method and route template;
- resource type and a lowercase SHA-256 hash of the server-selected resource identifier;
- allow or deny decision, bounded internal reason code and HTTP status;
- authorization-mode ID for access events and an optional sensitive-operation ID.

It has no generic metadata, headers, query, body, payload, certificate, cookie or response field. Raw resource identifiers are not stored. A failed gateway authentication records a denial with null tenant and actor because an unverified client claim is not authority. It still records the server-defined action, route and route hash. After authentication succeeds, both event kinds require the exact trusted tenant/subject membership pair.

## PostgreSQL projection

Migration `012_api_request_outcome_audit.sql` creates `audit.api_request_events`. The `tenant_trust_app` role has no direct table or sequence privileges. It can call only the security-definer `audit.record_api_request_event` function, whose table constraints independently enforce identifier formats, trusted actor pairing, event-kind fields, decision/status consistency and one event of each kind per request.

Rows are append-only. A trigger rejects update and delete even for the migration owner, while foreign keys retain the tenant membership needed to explain a historical decision. Tenant/time and correlation indexes support incident reconstruction without exposing raw request data. The later audit/Fabric phase may select and canonicalize these records, but T4.8 does not claim a Fabric commitment.

## Request sequence

1. The API creates request and correlation IDs and returns them in response headers.
2. The gateway resolver either returns a verified certificate identity or an authentication denial is captured without trusting caller headers.
3. A successful authentication event is committed before the protected repository is called.
4. The repository revalidates certificate and tenant state, evaluates the selected authorization mode and runs the tenant-scoped operation.
5. The API records the allow or bounded denial before returning the result. Successful sensitive operations include their repository-generated operation ID.

Schema and body-size failures occur before authentication and data access. They receive server-generated response correlation headers but are not mislabeled as authenticated actor events.

## Verification

`npm run request-outcomes:verify` runs API unit coverage, a rolled-back database privilege/constraint scenario and a rolled-back live API scenario. The live gate proves successful, denied and unauthenticated outcomes; exact actor/tenant/action/resource/decision fields; shared request correlation; sensitive-operation correlation; ignored forged correlation and identity headers; append-only least privilege; and absence of raw secrets, resource IDs and payloads. The audit transaction rolls back and disposable certificate inventory is removed on exit.
