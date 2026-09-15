# Gateway identity

`@tenant-trust/gateway-identity` converts a client certificate forwarded by the configured NGINX gateway into a bounded application authentication result.

The resolver first requires an authorized Node `TLSSocket` whose peer certificate exactly matches the configured gateway certificate. Only then does it read the four gateway-owned headers, parse the `tenant-client-auth-v1` subject and URI SAN, and verify the leaf against the current active issuer selected for that tenant. The output contains no roles or authorization decision.

An API TLS listener must use `requestCert: true`, `rejectUnauthorized: true` and the internal CA. Pass its raw request socket and headers directly to the resolver. Do not construct either input from request JSON, and do not use certificate, tenant or subject headers outside this boundary.

Run `npm run test:gateway-identity` for pure boundary tests and `npm run mtls-gateway:verify` for the disposable NGINX and two-leg TLS integration gate. See [mTLS gateway and application identity](../../docs/architecture/mtls-gateway-identity.md).
