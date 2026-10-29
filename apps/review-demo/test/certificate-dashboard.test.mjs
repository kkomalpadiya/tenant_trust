import assert from "node:assert/strict";
import { test } from "node:test";
import { CertificateDashboardError, createCertificateDashboard } from "../certificate-dashboard.mjs";
import { reviewIds } from "../demo-domain.mjs";

const clock = () => new Date("2026-10-27T10:00:00.000Z");

function idFactory() {
  let sequence = 0;
  return () => {
    sequence += 1;
    return `11111111-1111-4111-8111-${String(sequence).padStart(12, "0")}`;
  };
}

function dashboard() {
  return createCertificateDashboard({ clock, idFactory: idFactory() });
}

test("members see their own inventory but certificate controls are administrator-only", () => {
  const state = dashboard().getState("alpha-member");

  assert.equal(state.subjects.length, 1);
  assert.equal(state.subjects[0].subjectId, reviewIds.alice);
  assert.equal(state.certificates.length, 1);
  assert.ok(state.certificates.every(({ tenantId, subjectId }) => (
    tenantId === reviewIds.alphaTenant && subjectId === reviewIds.alice
  )));
  assert.equal(state.subjects[0].operations.issue.allowed, false);
  assert.equal(state.certificates[0].operations.renew.allowed, false);
  assert.equal(state.certificates[0].operations.revoke.allowed, false);
});

test("tenant administrators see only subjects and certificates from their tenant", () => {
  const alpha = dashboard().getState("alpha-admin");
  const beta = dashboard().getState("beta-admin");

  assert.deepEqual(alpha.subjects.map(({ subjectId }) => subjectId).sort(), [reviewIds.alice, reviewIds.alphaAdmin].sort());
  assert.ok(alpha.certificates.every(({ tenantId }) => tenantId === reviewIds.alphaTenant));
  assert.deepEqual(beta.subjects.map(({ subjectId }) => subjectId).sort(), [reviewIds.bob, reviewIds.betaAdmin].sort());
  assert.ok(beta.certificates.every(({ tenantId }) => tenantId === reviewIds.betaTenant));
});

test("issue, renew and revoke re-authorize and update only the scoped inventory", () => {
  const service = dashboard();
  const issued = service.execute({
    personaKey: "alpha-admin",
    operation: "issue",
    subjectId: reviewIds.alice,
  });
  assert.equal(issued.reasonCode, "CERTIFICATE_ISSUED");
  assert.equal(issued.certificate.tenantId, reviewIds.alphaTenant);
  assert.equal(issued.certificate.subjectId, reviewIds.alice);

  const renewed = service.execute({
    personaKey: "alpha-admin",
    operation: "renew",
    subjectId: reviewIds.alice,
    certificateId: "crt_018f1234-5678-7abc-8def-0123456789c1",
  });
  assert.equal(renewed.reasonCode, "CERTIFICATE_RENEWED");
  assert.equal(renewed.certificate.renewalOfCertificateId, "crt_018f1234-5678-7abc-8def-0123456789c1");

  const revoked = service.execute({
    personaKey: "alpha-admin",
    operation: "revoke",
    subjectId: reviewIds.alice,
    certificateId: issued.certificate.certificateId,
  });
  assert.equal(revoked.reasonCode, "CERTIFICATE_REVOKED");
  assert.equal(revoked.certificate.state, "revoked");

  const state = service.getState("alpha-admin");
  assert.equal(state.certificates.find(({ certificateId }) => certificateId === renewed.certificate.certificateId).state, "active");
  assert.equal(state.certificates.find(({ certificateId }) => certificateId === issued.certificate.certificateId).state, "revoked");
  assert.equal(state.certificates.find(({ certificateId }) => certificateId === "crt_018f1234-5678-7abc-8def-0123456789c1").state, "superseded");
  const memberState = service.getState("alpha-member");
  assert.equal(memberState.authenticationCertificate.state, "superseded");
  assert.equal(memberState.authenticationCertificate.isAuthenticationCertificate, true);
  assert.equal(memberState.authenticationCertificate.isCurrentCertificate, false);
  assert.equal(memberState.currentCertificate, null);
});

test("server-side authorization denies foreign and elevated targets", () => {
  const service = dashboard();

  assert.throws(
    () => service.execute({ personaKey: "alpha-member", operation: "issue", subjectId: reviewIds.alice }),
    (error) => error instanceof CertificateDashboardError
      && error.statusCode === 403
      && error.reasonCode === "ACCESS_DENIED",
  );
  assert.throws(
    () => service.execute({ personaKey: "alpha-member", operation: "issue", subjectId: reviewIds.alphaAdmin }),
    (error) => error instanceof CertificateDashboardError
      && error.statusCode === 403
      && error.reasonCode === "ACCESS_DENIED",
  );
  assert.throws(
    () => service.execute({ personaKey: "alpha-admin", operation: "issue", subjectId: reviewIds.bob }),
    (error) => error instanceof CertificateDashboardError
      && error.statusCode === 403
      && error.reasonCode === "ACCESS_DENIED",
  );
});

test("lifecycle state and renewal-window checks are enforced again on submission", () => {
  const service = dashboard();
  const mayaCertificate = "crt_018f1234-5678-7abc-8def-0123456789c2";

  assert.throws(
    () => service.execute({
      personaKey: "alpha-admin",
      operation: "renew",
      subjectId: reviewIds.alphaAdmin,
      certificateId: mayaCertificate,
    }),
    (error) => error instanceof CertificateDashboardError
      && error.statusCode === 409
      && error.reasonCode === "RENEWAL_WINDOW_CLOSED",
  );

  service.execute({
    personaKey: "alpha-admin",
    operation: "revoke",
    subjectId: reviewIds.alphaAdmin,
    certificateId: mayaCertificate,
  });
  assert.throws(
    () => service.execute({
      personaKey: "alpha-admin",
      operation: "revoke",
      subjectId: reviewIds.alphaAdmin,
      certificateId: mayaCertificate,
    }),
    (error) => error instanceof CertificateDashboardError
      && error.statusCode === 409
      && error.reasonCode === "CERTIFICATE_NOT_ACTIVE",
  );
});
