# Tenant certificate dashboard

## Boundary

Task T10.1 adds a tenant-facing subject and certificate view to the local review application. The browser receives only the inventory rows allowed for the authenticated demo persona. A tenant member sees their own subject and certificates. A tenant administrator sees subjects and certificates from the same tenant. No response includes another tenant's rows.

The review application uses deterministic identities and an in-memory certificate inventory so the dashboard can be demonstrated without private keys or a live certificate authority. This is a presentation adapter over the implemented certificate-lifecycle rules, not a replacement for the production issuance, renewal, revocation or inventory packages.

## Control authorization

The browser displays server-calculated issue, renew and revoke permissions. Display state is not authority. Every operation submitted to `POST /api/demo/certificates/operations` resolves the selected certificate persona again on the server and derives its immutable tenant context. The handler ignores caller-supplied tenant and role values and accepts only operation and target identifiers.

An operation proceeds only when all applicable checks pass:

- the target subject and certificate resolve inside the authenticated tenant;
- the target is the authenticated subject or the context contains `tenant-admin`;
- the subject and certificate are active when required;
- renewal is inside the final quarter of the certificate validity period; and
- revoke and renew are rejected after the certificate leaves `active` state.

Unknown and cross-tenant targets return the same `ACCESS_DENIED` result. Lifecycle conflicts return a specific safe state reason and do not change inventory.

## Demo state and audit

Successful controls update only the server's in-memory review inventory and add a sanitized event to the existing review audit trail. The event records actor, tenant, operation, outcome, correlation and the generic client-certificate resource class. It does not include a certificate identifier, private key, CSR or certificate payload. Restarting the server restores the deterministic starting inventory.

The focused verification command checks member and administrator visibility, cross-tenant denial, self-versus-admin authorization, renewal timing, terminal-state rejection and all three lifecycle mutations.
