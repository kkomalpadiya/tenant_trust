import { Context, Contract } from "fabric-contract-api";

const SCHEMA_VERSION = "1.0.0";
const CANONICALIZATION_PROFILE = "tenant-trust-audit-commitment-json-v1";
const DIGEST_ALGORITHM = "sha256";
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const RECORD_TYPES = new Set([
  "access-decision",
  "certificate-lifecycle",
  "policy-change",
  "security-action",
  "trust-transition",
]);
const LEDGER_FIELDS = [
  "canonicalizationProfile",
  "commitmentHashSha256",
  "digestAlgorithm",
  "eventKeyHashSha256",
  "recordType",
  "schemaVersion",
];
const CHANNEL_TENANT_AUDITOR_MSP = new Map([
  ["tt-audit-alpha-v1", "TenantAlphaAuditMSP"],
  ["tt-audit-beta-v1", "TenantBetaAuditMSP"],
]);

type RecordType =
  | "access-decision"
  | "certificate-lifecycle"
  | "policy-change"
  | "security-action"
  | "trust-transition";

interface AuditLedgerValue {
  canonicalizationProfile: typeof CANONICALIZATION_PROFILE;
  commitmentHashSha256: string;
  digestAlgorithm: typeof DIGEST_ALGORITHM;
  eventKeyHashSha256: string;
  recordType: RecordType;
  schemaVersion: typeof SCHEMA_VERSION;
}

function fail(code: string, detail: string): never {
  throw new Error(`${code}: ${detail}`);
}

function assertKnownChannel(ctx: Context): string {
  const channelId = ctx.stub.getChannelID();
  if (!CHANNEL_TENANT_AUDITOR_MSP.has(channelId)) {
    fail("UNSUPPORTED_CHANNEL", "audit commitments are restricted to configured tenant channels");
  }
  return channelId;
}

function hasRole(ctx: Context, role: string): boolean {
  return ctx.clientIdentity.assertAttributeValue("tenantTrust.role", role);
}

function assertWriter(ctx: Context): void {
  assertKnownChannel(ctx);
  if (ctx.clientIdentity.getMSPID() !== "PlatformAuditMSP" || !hasRole(ctx, "audit-writer")) {
    fail("FORBIDDEN", "CommitCommitment requires the PlatformAuditMSP audit-writer identity");
  }
}

function assertReader(ctx: Context): void {
  const channelId = assertKnownChannel(ctx);
  const mspId = ctx.clientIdentity.getMSPID();
  const platformVerifier = mspId === "PlatformAuditMSP" && hasRole(ctx, "audit-verifier");
  const tenantAuditor = mspId === CHANNEL_TENANT_AUDITOR_MSP.get(channelId) && hasRole(ctx, "tenant-auditor");
  if (!platformVerifier && !tenantAuditor) {
    fail("FORBIDDEN", "ReadCommitment requires the platform verifier or this channel's tenant auditor");
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function parseCommitment(input: string): AuditLedgerValue {
  if (typeof input !== "string" || input.length === 0 || input.length > 2048) {
    fail("INVALID_COMMITMENT", "commitment JSON must contain between 1 and 2048 characters");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch {
    fail("INVALID_COMMITMENT", "commitment must be valid JSON");
  }
  if (!isPlainObject(parsed)) fail("INVALID_COMMITMENT", "commitment must be a JSON object");
  const keys = Object.keys(parsed).sort();
  if (keys.length !== LEDGER_FIELDS.length || !keys.every((key, index) => key === LEDGER_FIELDS[index])) {
    fail("INVALID_COMMITMENT", "commitment contains missing or unapproved public fields");
  }
  if (parsed.schemaVersion !== SCHEMA_VERSION) fail("INVALID_COMMITMENT", "unsupported schemaVersion");
  if (typeof parsed.recordType !== "string" || !RECORD_TYPES.has(parsed.recordType)) {
    fail("INVALID_COMMITMENT", "unsupported recordType");
  }
  if (typeof parsed.eventKeyHashSha256 !== "string" || !SHA256_PATTERN.test(parsed.eventKeyHashSha256)) {
    fail("INVALID_COMMITMENT", "invalid eventKeyHashSha256");
  }
  if (typeof parsed.commitmentHashSha256 !== "string" || !SHA256_PATTERN.test(parsed.commitmentHashSha256)) {
    fail("INVALID_COMMITMENT", "invalid commitmentHashSha256");
  }
  if (parsed.canonicalizationProfile !== CANONICALIZATION_PROFILE) {
    fail("INVALID_COMMITMENT", "unsupported canonicalizationProfile");
  }
  if (parsed.digestAlgorithm !== DIGEST_ALGORITHM) fail("INVALID_COMMITMENT", "unsupported digestAlgorithm");

  return {
    canonicalizationProfile: CANONICALIZATION_PROFILE,
    commitmentHashSha256: parsed.commitmentHashSha256,
    digestAlgorithm: DIGEST_ALGORITHM,
    eventKeyHashSha256: parsed.eventKeyHashSha256,
    recordType: parsed.recordType as RecordType,
    schemaVersion: SCHEMA_VERSION,
  };
}

function assertRecordType(recordType: string): asserts recordType is RecordType {
  if (!RECORD_TYPES.has(recordType)) fail("INVALID_QUERY", "unsupported recordType");
}

function assertEventKeyHash(eventKeyHashSha256: string): void {
  if (!SHA256_PATTERN.test(eventKeyHashSha256)) fail("INVALID_QUERY", "invalid eventKeyHashSha256");
}

function commitmentKey(value: Pick<AuditLedgerValue, "recordType" | "eventKeyHashSha256">): string {
  return `audit~${value.recordType}~${value.eventKeyHashSha256}`;
}

function eventAnchorKey(eventKeyHashSha256: string): string {
  return `event~${eventKeyHashSha256}`;
}

function serializeCommitment(value: AuditLedgerValue): Buffer {
  return Buffer.from(JSON.stringify(value), "utf8");
}

export class TenantTrustAuditContract extends Contract {
  constructor() {
    super("TenantTrustAudit");
  }

  public async CommitCommitment(ctx: Context, commitmentJson: string): Promise<string> {
    assertWriter(ctx);
    const value = parseCommitment(commitmentJson);
    const key = commitmentKey(value);
    const anchorKey = eventAnchorKey(value.eventKeyHashSha256);
    const expectedState = serializeCommitment(value);
    const expectedAnchor = Buffer.from(key, "utf8");
    const [currentState, currentAnchor] = await Promise.all([
      ctx.stub.getState(key),
      ctx.stub.getState(anchorKey),
    ]);

    const stateExists = currentState.length > 0;
    const anchorExists = currentAnchor.length > 0;
    if (stateExists || anchorExists) {
      if (anchorExists && !Buffer.from(currentAnchor).equals(expectedAnchor)) {
        fail("CONFLICTING_EVENT_ANCHOR", "the opaque event key is already bound to another commitment key");
      }
      if (!stateExists || !anchorExists) {
        fail("INCONSISTENT_STATE", "commitment and event anchor must either both exist or both be absent");
      }
      if (!Buffer.from(currentState).equals(expectedState)) {
        fail("CONFLICTING_COMMITMENT", "the commitment key already exists with different bytes");
      }
      return JSON.stringify({ ledgerKey: key, status: "duplicate" });
    }

    await ctx.stub.putState(key, expectedState);
    await ctx.stub.putState(anchorKey, expectedAnchor);
    ctx.stub.setEvent("AuditCommitmentCreated", Buffer.from(JSON.stringify({
      commitmentHashSha256: value.commitmentHashSha256,
      eventKeyHashSha256: value.eventKeyHashSha256,
      ledgerKey: key,
      recordType: value.recordType,
      schemaVersion: value.schemaVersion,
    }), "utf8"));
    return JSON.stringify({ ledgerKey: key, status: "created" });
  }

  public async ReadCommitment(ctx: Context, recordType: string, eventKeyHashSha256: string): Promise<string> {
    assertReader(ctx);
    assertRecordType(recordType);
    assertEventKeyHash(eventKeyHashSha256);
    const key = commitmentKey({ recordType, eventKeyHashSha256 });
    const state = await ctx.stub.getState(key);
    if (state.length === 0) fail("COMMITMENT_NOT_FOUND", "no commitment exists for the supplied opaque key");
    return Buffer.from(state).toString("utf8");
  }
}
