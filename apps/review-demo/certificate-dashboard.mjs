import { createHash, randomUUID } from "node:crypto";
import { getReviewPersona, personas, resolveReviewContext, reviewIds } from "./demo-domain.mjs";

const OPERATIONS = new Set(["issue", "renew", "revoke"]);

const subjectDefinitions = Object.freeze([
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    subjectId: reviewIds.alice,
    displayName: personas["alpha-member"].displayName,
    initials: personas["alpha-member"].initials,
    role: "tenant-member",
    roleLabel: "Tenant member",
    state: "active",
  }),
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    subjectId: reviewIds.alphaAdmin,
    displayName: personas["alpha-admin"].displayName,
    initials: personas["alpha-admin"].initials,
    role: "tenant-admin",
    roleLabel: "Tenant administrator",
    state: "active",
  }),
  Object.freeze({
    tenantId: reviewIds.betaTenant,
    subjectId: reviewIds.bob,
    displayName: "Bob Patel",
    initials: "BP",
    role: "tenant-member",
    roleLabel: "Tenant member",
    state: "active",
  }),
  Object.freeze({
    tenantId: reviewIds.betaTenant,
    subjectId: reviewIds.betaAdmin,
    displayName: personas["beta-admin"].displayName,
    initials: personas["beta-admin"].initials,
    role: "tenant-admin",
    roleLabel: "Tenant administrator",
    state: "active",
  }),
]);

const initialCertificates = Object.freeze([
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    certificateId: personas["alpha-member"].certificateId,
    subjectId: reviewIds.alice,
    issuer: personas["alpha-member"].tenant.issuer,
    serial: personas["alpha-member"].serial,
    fingerprint: personas["alpha-member"].fingerprint,
    state: "active",
    notBefore: "2026-01-16T10:30:00.000Z",
    expiresOn: "2027-01-16T10:30:00.000Z",
    updatedAt: "2026-09-17T08:30:00.000Z",
    renewalOfCertificateId: null,
  }),
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    certificateId: personas["alpha-admin"].certificateId,
    subjectId: reviewIds.alphaAdmin,
    issuer: personas["alpha-admin"].tenant.issuer,
    serial: personas["alpha-admin"].serial,
    fingerprint: personas["alpha-admin"].fingerprint,
    state: "active",
    notBefore: "2026-06-21T08:15:00.000Z",
    expiresOn: "2027-06-21T08:15:00.000Z",
    updatedAt: "2026-09-17T08:30:00.000Z",
    renewalOfCertificateId: null,
  }),
  Object.freeze({
    tenantId: reviewIds.betaTenant,
    certificateId: "crt_018f1234-5678-7abc-8def-0123456789c4",
    subjectId: reviewIds.bob,
    issuer: personas["beta-admin"].tenant.issuer,
    serial: "2B:19:6F:40:88:D2",
    fingerprint: "31:EF:48:A2:10:B9:77:4C",
    state: "active",
    notBefore: "2026-04-04T11:24:00.000Z",
    expiresOn: "2027-04-04T11:24:00.000Z",
    updatedAt: "2026-09-17T08:30:00.000Z",
    renewalOfCertificateId: null,
  }),
  Object.freeze({
    tenantId: reviewIds.betaTenant,
    certificateId: personas["beta-admin"].certificateId,
    subjectId: reviewIds.betaAdmin,
    issuer: personas["beta-admin"].tenant.issuer,
    serial: personas["beta-admin"].serial,
    fingerprint: personas["beta-admin"].fingerprint,
    state: "active",
    notBefore: "2026-01-08T16:45:00.000Z",
    expiresOn: "2027-01-08T16:45:00.000Z",
    updatedAt: "2026-09-17T08:30:00.000Z",
    renewalOfCertificateId: null,
  }),
]);

export class CertificateDashboardError extends Error {
  constructor(reasonCode, statusCode = 403) {
    super("Certificate operation denied.");
    this.name = "CertificateDashboardError";
    this.reasonCode = reasonCode;
    this.statusCode = statusCode;
  }
}

function requireDate(value, reasonCode) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new CertificateDashboardError(reasonCode, 500);
  return date;
}

function canManageSubject(context, subject) {
  return subject.tenantId === context.tenantId
    && subject.state === "active"
    && (subject.subjectId === context.subjectId || context.roles.includes("tenant-admin"));
}

function renewalWindowOpen(certificate, now) {
  const notBefore = requireDate(certificate.notBefore, "CERTIFICATE_TIME_INVALID");
  const notAfter = requireDate(certificate.expiresOn, "CERTIFICATE_TIME_INVALID");
  const validityMs = notAfter.getTime() - notBefore.getTime();
  return certificate.state === "active"
    && validityMs > 0
    && now >= notBefore
    && now < notAfter
    && now.getTime() >= notAfter.getTime() - validityMs / 4;
}

function permission(allowed, allowedReason, deniedReason) {
  return Object.freeze({
    allowed,
    reasonCode: allowed ? allowedReason : deniedReason,
  });
}

function issuePermission(context, subject) {
  return permission(
    canManageSubject(context, subject),
    subject.subjectId === context.subjectId ? "SELF_ENROLLMENT_ALLOWED" : "TENANT_ADMIN_ENROLLMENT_ALLOWED",
    "SUBJECT_ENROLLMENT_UNAUTHORIZED",
  );
}

function certificatePermission(context, subject, certificate, operation, now) {
  if (!canManageSubject(context, subject) || certificate.tenantId !== context.tenantId) {
    return permission(false, "", "CERTIFICATE_OPERATION_UNAUTHORIZED");
  }
  if (certificate.state !== "active") {
    return permission(false, "", "CERTIFICATE_NOT_ACTIVE");
  }
  if (operation === "renew" && !renewalWindowOpen(certificate, now)) {
    return permission(false, "", "RENEWAL_WINDOW_CLOSED");
  }
  return permission(
    true,
    subject.subjectId === context.subjectId ? "SELF_OPERATION_ALLOWED" : "TENANT_ADMIN_OPERATION_ALLOWED",
    "CERTIFICATE_OPERATION_UNAUTHORIZED",
  );
}

function compactSubject(subject, context) {
  return Object.freeze({
    ...subject,
    isCurrentSubject: subject.subjectId === context.subjectId,
    operations: Object.freeze({ issue: issuePermission(context, subject) }),
  });
}

function compactCertificate(certificate, subject, context, currentCertificateId, now) {
  return Object.freeze({
    ...certificate,
    subjectName: subject.displayName,
    isCurrentCertificate: certificate.certificateId === currentCertificateId,
    operations: Object.freeze({
      renew: certificatePermission(context, subject, certificate, "renew", now),
      revoke: certificatePermission(context, subject, certificate, "revoke", now),
    }),
  });
}

function generatedCertificate({ tenantId, subjectId, issuer, renewalOfCertificateId, now, idFactory }) {
  const certificateId = `crt_${idFactory()}`;
  const digest = createHash("sha256").update(certificateId, "utf8").digest("hex").toUpperCase();
  const serial = digest.slice(0, 12).match(/../gu).join(":");
  const fingerprint = digest.slice(12, 28).match(/../gu).join(":");
  return {
    tenantId,
    certificateId,
    subjectId,
    issuer,
    serial,
    fingerprint,
    state: "active",
    notBefore: now.toISOString(),
    expiresOn: new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: now.toISOString(),
    renewalOfCertificateId,
  };
}

function operationEvent({ persona, operation, now, sequence }) {
  const reasonCodes = {
    issue: "CERTIFICATE_ISSUED",
    renew: "CERTIFICATE_RENEWED",
    revoke: "CERTIFICATE_REVOKED",
  };
  return Object.freeze({
    id: `evt_dashboard_${now.getTime()}_${sequence}`,
    occurredAt: now.toISOString(),
    actor: persona.displayName,
    tenant: persona.tenant.name,
    action: `certificate:${operation}`,
    resource: "client-certificate",
    outcome: "allow",
    statusCode: 200,
    reasonCode: reasonCodes[operation],
    correlationId: `cor_dashboard_${sequence}`,
  });
}

export function createCertificateDashboard({ clock = () => new Date(), idFactory = randomUUID } = {}) {
  if (typeof clock !== "function" || typeof idFactory !== "function") {
    throw new TypeError("Certificate dashboard clock and ID factory must be functions.");
  }
  const subjects = subjectDefinitions.map((subject) => ({ ...subject }));
  const certificates = initialCertificates.map((certificate) => ({ ...certificate }));
  let eventSequence = 0;

  function getState(personaKey = "alpha-member") {
    const persona = getReviewPersona(personaKey);
    const context = resolveReviewContext(personaKey);
    const now = requireDate(clock(), "DASHBOARD_TIME_INVALID");
    const visibleSubjects = subjects.filter((subject) => subject.tenantId === context.tenantId
      && (subject.subjectId === context.subjectId || context.roles.includes("tenant-admin")));
    const subjectIds = new Set(visibleSubjects.map(({ subjectId }) => subjectId));
    const visibleCertificates = certificates.filter((certificate) => (
      certificate.tenantId === context.tenantId && subjectIds.has(certificate.subjectId)
    ));
    const compactSubjects = visibleSubjects.map((subject) => compactSubject(subject, context));
    const compactCertificates = visibleCertificates.map((certificate) => compactCertificate(
      certificate,
      visibleSubjects.find(({ subjectId }) => subjectId === certificate.subjectId),
      context,
      persona.certificateId,
      now,
    ));
    const permittedOperations = compactSubjects.filter(({ operations }) => operations.issue.allowed).length
      + compactCertificates.reduce((count, certificate) => count
        + Number(certificate.operations.renew.allowed)
        + Number(certificate.operations.revoke.allowed), 0);
    return Object.freeze({
      subjects: Object.freeze(compactSubjects),
      certificates: Object.freeze(compactCertificates),
      certificateSummary: Object.freeze({
        subjectCount: compactSubjects.length,
        certificateCount: compactCertificates.length,
        activeCertificateCount: compactCertificates.filter(({ state }) => state === "active").length,
        permittedOperations,
      }),
      currentCertificate: compactCertificates.find(({ certificateId }) => certificateId === persona.certificateId) ?? null,
    });
  }

  function execute({ personaKey = "alpha-member", operation, subjectId, certificateId = null } = {}) {
    if (!OPERATIONS.has(operation)) throw new CertificateDashboardError("CERTIFICATE_OPERATION_INVALID", 400);
    const persona = getReviewPersona(personaKey);
    const context = resolveReviewContext(personaKey);
    const now = requireDate(clock(), "DASHBOARD_TIME_INVALID");
    const subject = subjects.find((candidate) => candidate.subjectId === subjectId
      && candidate.tenantId === context.tenantId);
    if (!subject) throw new CertificateDashboardError("ACCESS_DENIED");

    let certificate;
    if (operation === "issue") {
      const decision = issuePermission(context, subject);
      if (!decision.allowed) throw new CertificateDashboardError("ACCESS_DENIED");
      certificate = generatedCertificate({
        tenantId: context.tenantId,
        subjectId: subject.subjectId,
        issuer: persona.tenant.issuer,
        renewalOfCertificateId: null,
        now,
        idFactory,
      });
      certificates.push(certificate);
    } else {
      const target = certificates.find((candidate) => candidate.certificateId === certificateId
        && candidate.subjectId === subject.subjectId
        && candidate.tenantId === context.tenantId);
      if (!target) throw new CertificateDashboardError("ACCESS_DENIED");
      const decision = certificatePermission(context, subject, target, operation, now);
      if (!decision.allowed) throw new CertificateDashboardError(decision.reasonCode, 409);
      if (operation === "renew") {
        target.state = "superseded";
        target.updatedAt = now.toISOString();
        certificate = generatedCertificate({
          tenantId: context.tenantId,
          subjectId: subject.subjectId,
          issuer: target.issuer,
          renewalOfCertificateId: target.certificateId,
          now,
          idFactory,
        });
        certificates.push(certificate);
      } else {
        target.state = "revoked";
        target.updatedAt = now.toISOString();
        target.revokedAt = now.toISOString();
        certificate = target;
      }
    }

    eventSequence += 1;
    const event = operationEvent({ persona, operation, now, sequence: eventSequence });
    return Object.freeze({
      statusCode: 200,
      outcome: "allow",
      reasonCode: event.reasonCode,
      headline: operation === "issue" ? "Certificate issued"
        : operation === "renew" ? "Certificate renewed" : "Certificate revoked",
      summary: `${subject.displayName}'s certificate inventory was updated in the local review session.`,
      certificate: Object.freeze({ ...certificate }),
      event,
    });
  }

  return Object.freeze({ getState, execute });
}
