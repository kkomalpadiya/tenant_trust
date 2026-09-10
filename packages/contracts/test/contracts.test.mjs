import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const schemaRoot = fileURLToPath(new URL('../schemas/', import.meta.url));
const common = JSON.parse(readFileSync(`${schemaRoot}/common.schema.json`, 'utf8'));
const registry = JSON.parse(readFileSync(`${schemaRoot}/event-registry.json`, 'utf8'));
const schemaFiles = readdirSync(`${schemaRoot}/events`).filter((file) => file.endsWith('.schema.json')).sort();
const schemas = Object.fromEntries(schemaFiles.map((file) => [file, JSON.parse(readFileSync(`${schemaRoot}/events/${file}`, 'utf8'))]));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(common);
const validators = Object.fromEntries(Object.entries(schemas).map(([file, schema]) => [file, ajv.compile(schema)]));

const ids = {
  tenant: 'tnt_018f1234-5678-7abc-8def-0123456789ab',
  subject: 'sub_018f1234-5678-7abc-8def-0123456789ab',
  certificate: 'crt_018f1234-5678-7abc-8def-0123456789ab',
  issuer: 'iss_018f1234-5678-7abc-8def-0123456789ab',
  source: 'src_018f1234-5678-7abc-8def-0123456789ab',
  evidence: 'evd_018f1234-5678-7abc-8def-0123456789ab',
  transition: 'trn_018f1234-5678-7abc-8def-0123456789ab',
  policy: 'pol_018f1234-5678-7abc-8def-0123456789ab',
  request: 'req_018f1234-5678-7abc-8def-0123456789ab',
  decision: 'dec_018f1234-5678-7abc-8def-0123456789ab',
  action: 'act_018f1234-5678-7abc-8def-0123456789ab',
  correlation: 'cor_018f1234-5678-7abc-8def-0123456789ab'
};
const hash = 'ab'.repeat(32);
function envelope(number, eventType, aggregateId, payload, overrides = {}) {
  return {
    schemaVersion: '1.0.0',
    eventId: `evt_018f1234-5678-7abc-8def-${String(number).padStart(12, '0')}`,
    eventType,
    tenantId: ids.tenant,
    subjectId: ids.subject,
    aggregateId,
    correlationId: ids.correlation,
    causationId: number === 1 ? null : `evt_018f1234-5678-7abc-8def-${String(number - 1).padStart(12, '0')}`,
    idempotencyKey: `demo:tenant-alpha:${eventType}:${number}`,
    occurredAt: `2026-09-10T10:${String(number).padStart(2, '0')}:00.000Z`,
    recordedAt: `2026-09-10T10:${String(number).padStart(2, '0')}:01.000Z`,
    producer: { service: 'contract-test', instanceId: 'test-1' },
    payload,
    ...overrides
  };
}
const events = {
  'tenant-event.schema.json': envelope(1, 'tenant.created.v1', ids.tenant, { state: 'active', displayName: 'Tenant Alpha' }, { subjectId: null }),
  'subject-event.schema.json': envelope(2, 'subject.provisioned.v1', ids.subject, { state: 'active', roles: ['tenant-member'] }),
  'certificate-event.schema.json': envelope(3, 'certificate.issued.v1', ids.certificate, { certificateId: ids.certificate, issuerId: ids.issuer, serialNumber: '01AF', fingerprintSha256: hash, state: 'active', notBefore: '2026-09-10T10:03:00.000Z', notAfter: '2026-10-10T10:03:00.000Z', supersedesCertificateId: null }),
  'evidence-event.schema.json': envelope(4, 'evidence.accepted.v1', ids.evidence, { evidenceId: ids.evidence, sourceId: ids.source, evidenceType: 'device', observedAt: '2026-09-10T10:03:30.000Z', expiresAt: '2026-09-10T10:20:00.000Z', sourceSequence: 7, contentHashSha256: hash, synthetic: true }),
  'trust-event.schema.json': envelope(5, 'trust.updated.v1', ids.transition, { transitionId: ids.transition, previousScore: 86, newScore: 62, previousBand: 'trusted', newBand: 'restricted', modelVersion: '1.0.0', configurationVersion: 1, evidenceIds: [ids.evidence], explanationHashSha256: hash }),
  'policy-event.schema.json': envelope(6, 'policy.activated.v1', ids.policy, { policyVersionId: ids.policy, bundleVersion: 1, bundleHashSha256: hash, state: 'active', replacesPolicyVersionId: null }),
  'decision-event.schema.json': envelope(7, 'access.decided.v1', ids.decision, { decisionId: ids.decision, requestId: ids.request, certificateId: ids.certificate, trustTransitionId: ids.transition, trustScore: 62, policyVersionId: ids.policy, operation: 'record:export', resourceType: 'tenant-records', resourceIdHashSha256: hash, outcome: 'DENY', reasonCodes: ['TRUST_BELOW_EXPORT_THRESHOLD'], stepUpProofIdHashSha256: null }),
  'action-event.schema.json': envelope(8, 'security-action.requested.v1', ids.action, { actionId: ids.action, decisionId: ids.decision, actionType: 'restrict-access', status: 'requested', targetCertificateId: ids.certificate, reasonCode: 'TRUST_RESTRICTED' })
};

test('all eight domain schemas compile and accept representative events', () => {
  assert.equal(Object.keys(validators).length, 8);
  for (const [file, validate] of Object.entries(validators)) {
    assert.equal(validate(events[file]), true, `${file}: ${ajv.errorsText(validate.errors)}`);
  }
});

test('the registry maps every declared event type to its owning schema', () => {
  const declared = new Map();
  for (const [file, schema] of Object.entries(schemas)) {
    const eventType = schema.allOf[1].properties.eventType;
    const names = eventType.enum ?? [eventType.const];
    for (const name of names) {
      assert.equal(declared.has(name), false, `duplicate event type: ${name}`);
      declared.set(name, `events/${file}`);
    }
  }
  assert.deepEqual(Object.fromEntries([...declared].sort()), Object.fromEntries(Object.entries(registry.events).sort()));
  assert.equal(registry.registryVersion, '1.0.0');
});

test('the sample chain links each event to its immediate cause and one correlation', () => {
  const chain = Object.values(events);
  for (let index = 0; index < chain.length; index++) {
    assert.equal(chain[index].correlationId, ids.correlation);
    assert.equal(chain[index].causationId, index === 0 ? null : chain[index - 1].eventId);
    assert.ok(Date.parse(chain[index].recordedAt) >= Date.parse(chain[index].occurredAt));
  }
});

test('malformed tenant IDs, local timestamps, scores and unknown fields are rejected', () => {
  const cases = [
    ['tenant-event.schema.json', { ...structuredClone(events['tenant-event.schema.json']), tenantId: 'tenant-alpha' }],
    ['evidence-event.schema.json', { ...structuredClone(events['evidence-event.schema.json']), occurredAt: '2026-09-10T10:04:00+05:30' }],
    ['trust-event.schema.json', { ...structuredClone(events['trust-event.schema.json']), payload: { ...events['trust-event.schema.json'].payload, newScore: 101 } }],
    ['decision-event.schema.json', { ...structuredClone(events['decision-event.schema.json']), unexpected: true }]
  ];
  for (const [file, event] of cases) assert.equal(validators[file](event), false, `${file} unexpectedly accepted invalid input`);
});

test('rejection, revocation and failure events require their reason fields', () => {
  const revoked = envelope(9, 'certificate.revoked.v1', ids.certificate, { certificateId: ids.certificate, issuerId: ids.issuer, serialNumber: '01AF', fingerprintSha256: hash, state: 'revoked', reasonCode: 'KEY_COMPROMISE' });
  assert.equal(validators['certificate-event.schema.json'](revoked), true);
  delete revoked.payload.reasonCode;
  assert.equal(validators['certificate-event.schema.json'](revoked), false);

  const rejected = { ...structuredClone(events['evidence-event.schema.json']), eventType: 'evidence.rejected.v1' };
  assert.equal(validators['evidence-event.schema.json'](rejected), false);
  rejected.payload.rejectionCode = 'SIGNATURE_INVALID';
  assert.equal(validators['evidence-event.schema.json'](rejected), true);

  const failed = { ...structuredClone(events['action-event.schema.json']), eventType: 'security-action.failed.v1', payload: { ...events['action-event.schema.json'].payload, status: 'failed' } };
  assert.equal(validators['action-event.schema.json'](failed), false);
  failed.payload.failureCode = 'CA_UNAVAILABLE';
  assert.equal(validators['action-event.schema.json'](failed), true);
});
