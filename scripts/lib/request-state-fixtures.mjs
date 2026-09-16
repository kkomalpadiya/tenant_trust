import { randomBytes, randomUUID } from "node:crypto";

const definitions = Object.freeze({
  alphaMember: Object.freeze({
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
    subjectId: "sub_018f1234-5678-7abc-8def-0123456789ab",
    issuerId: "iss_018f1234-5678-7abc-8def-0123456789b4",
  }),
  alphaAdmin: Object.freeze({
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
    subjectId: "sub_018f1234-5678-7abc-8def-0123456789ac",
    issuerId: "iss_018f1234-5678-7abc-8def-0123456789b4",
  }),
  betaMember: Object.freeze({
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ac",
    subjectId: "sub_018f1234-5678-7abc-8def-0123456789ad",
    issuerId: "iss_018f1234-5678-7abc-8def-0123456789b5",
  }),
});

function opaque(prefix) {
  return `${prefix}_${randomUUID()}`;
}

function buildIdentity(definition, now) {
  const fingerprintSha256 = randomBytes(32).toString("hex");
  const generatedSerial = randomBytes(16).toString("hex").toUpperCase();
  const serialNumber = /^0+$/u.test(generatedSerial) ? "01".padEnd(32, "0") : generatedSerial;
  const certificateId = opaque("crt");
  const issuedAt = new Date(now.getTime() - 60_000);
  const notBefore = new Date(now.getTime() - 300_000);
  const notAfter = new Date(now.getTime() + 3_600_000);
  return Object.freeze({
    certificateId,
    authentication: Object.freeze({
      source: "mtls-certificate",
      authenticationId: `sha256:${fingerprintSha256}`,
      tenantId: definition.tenantId,
      subjectId: definition.subjectId,
      certificate: Object.freeze({
        profileId: "tenant-client-auth-v1",
        issuerId: definition.issuerId,
        serialNumber,
        fingerprintSha256,
        publicKeySha256: randomBytes(32).toString("hex"),
        notBefore: notBefore.toISOString(),
        notAfter: notAfter.toISOString(),
      }),
    }),
    issuedAt,
  });
}

export async function createLiveRequestStateFixture(pool, { now = new Date() } = {}) {
  if (!pool || typeof pool.query !== "function") throw new TypeError("A PostgreSQL control pool is required.");
  const entries = Object.fromEntries(
    Object.entries(definitions).map(([name, definition]) => [name, buildIdentity(definition, now)]),
  );
  const inserted = [];
  try {
    for (const entry of Object.values(entries)) {
      const authentication = entry.authentication;
      await pool.query(
        `INSERT INTO identity.certificates (
           tenant_id, certificate_id, subject_id, issuer_id, profile_id, serial_number,
           fingerprint_sha256, public_key_algorithm, state, not_before, not_after,
           issued_at, state_changed_at, requested_by_subject_id, request_id,
           idempotency_key, issued_event_id, last_event_id, correlation_id
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7, 'ecdsa-p256', 'active', $8, $9,
           $10, $10, $3, $11, $12, $13, $13, $14
         )`,
        [
          authentication.tenantId,
          entry.certificateId,
          authentication.subjectId,
          authentication.certificate.issuerId,
          authentication.certificate.profileId,
          authentication.certificate.serialNumber,
          authentication.certificate.fingerprintSha256,
          authentication.certificate.notBefore,
          authentication.certificate.notAfter,
          entry.issuedAt,
          opaque("req"),
          `request-state:${randomUUID()}`,
          opaque("evt"),
          opaque("cor"),
        ],
      );
      inserted.push(entry.certificateId);
    }
  } catch (error) {
    if (inserted.length > 0) {
      await pool.query("DELETE FROM identity.certificates WHERE certificate_id = ANY($1::identity.certificate_id[])", [inserted]);
    }
    throw error;
  }

  const identities = Object.freeze(Object.fromEntries(
    Object.entries(entries).map(([name, entry]) => [name, entry.authentication]),
  ));
  return Object.freeze({
    identities,
    certificateIds: Object.freeze(Object.fromEntries(
      Object.entries(entries).map(([name, entry]) => [name, entry.certificateId]),
    )),
    async cleanup() {
      await pool.query(
        "DELETE FROM identity.certificates WHERE certificate_id = ANY($1::identity.certificate_id[])",
        [Object.values(entries).map((entry) => entry.certificateId)],
      );
    },
  });
}
