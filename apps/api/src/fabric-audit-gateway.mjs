import { createPrivateKey } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import * as grpc from "@grpc/grpc-js";
import { connect, hash, signers } from "@hyperledger/fabric-gateway";
import fabricProtos from "@hyperledger/fabric-protos";
import { assertAuditLedgerValue } from "@tenant-trust/contracts/audit-commitments";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const ENDPOINT = /^(?:127\.0\.0\.1|localhost|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?):[1-9][0-9]{0,4}$/u;
const SERVER_NAME = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/u;
const RESPONSE_STATUS = new Set(["created", "duplicate"]);
const SUBMIT_FIELDS = ["ledgerValue", "tenantId"];
const READ_FIELDS = ["eventKeyHashSha256", "recordType", "tenantId"];
const STATUS_FIELDS = ["tenantId", "transactionId"];
const decoder = new TextDecoder("utf-8", { fatal: true });

export const FABRIC_AUDIT_GATEWAY_POLICY = Object.freeze({
  chaincodeName: "tenant-trust-audit",
  contractName: "TenantTrustAudit",
  mspId: "PlatformAuditMSP",
  queryRole: "audit-verifier",
  submitRole: "audit-writer",
  requestTimeoutMilliseconds: 10_000,
});

export class FabricAuditGatewayError extends Error {
  constructor(reasonCode, options) {
    super("The internal Fabric audit gateway operation failed.", options);
    this.name = "FabricAuditGatewayError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode, cause) {
  throw new FabricAuditGatewayError(reasonCode, cause === undefined ? undefined : { cause });
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertExactFields(value, expected, label) {
  if (!isPlainObject(value)) throw new TypeError(`${label} must be a plain object.`);
  const fields = Object.keys(value).sort();
  if (fields.length !== expected.length || !fields.every((field, index) => field === expected[index])) {
    throw new TypeError(`${label} contains missing or unsupported fields.`);
  }
}

function parseJsonResult(bytes, reasonCode) {
  try {
    const value = JSON.parse(decoder.decode(bytes));
    if (!isPlainObject(value)) fail(reasonCode);
    return value;
  } catch (error) {
    if (error instanceof FabricAuditGatewayError) throw error;
    fail(reasonCode, error);
  }
}

function buildChannelMap(topology) {
  if (!isPlainObject(topology)
    || topology.schemaVersion !== "1.0.0"
    || topology.chaincode?.name !== FABRIC_AUDIT_GATEWAY_POLICY.chaincodeName
    || !Array.isArray(topology.channels)) {
    throw new TypeError("A supported Fabric topology is required.");
  }
  const channels = new Map();
  for (const channel of topology.channels) {
    if (!isPlainObject(channel)
      || !TENANT_ID.test(channel.tenantId ?? "")
      || typeof channel.name !== "string"
      || !channel.permissions?.submitCommitment?.some(({ mspId, role }) => (
        mspId === FABRIC_AUDIT_GATEWAY_POLICY.mspId && role === FABRIC_AUDIT_GATEWAY_POLICY.submitRole
      ))
      || !channel.permissions?.queryCommitment?.some(({ mspId, role }) => (
        mspId === FABRIC_AUDIT_GATEWAY_POLICY.mspId && role === FABRIC_AUDIT_GATEWAY_POLICY.queryRole
      ))) {
      throw new TypeError("Fabric topology does not grant the required separated gateway roles.");
    }
    if (channels.has(channel.tenantId)) throw new TypeError("Fabric topology maps one tenant to multiple channels.");
    channels.set(channel.tenantId, channel.name);
  }
  if (channels.size === 0) throw new TypeError("Fabric topology does not define tenant audit channels.");
  return channels;
}

function expectedLedgerKey(ledgerValue) {
  return `audit~${ledgerValue.recordType}~${ledgerValue.eventKeyHashSha256}`;
}

function validatedCommitStatus(status, source, transactionId) {
  const validationCode = Number(status?.code ?? status?.validationCode);
  const blockNumber = status?.blockNumber;
  if (status?.transactionId !== transactionId
      || !Number.isSafeInteger(validationCode)
      || validationCode < 0
      || (typeof blockNumber !== "bigint" && !Number.isSafeInteger(blockNumber))) {
    fail("COMMIT_STATUS_INVALID");
  }
  return Object.freeze({
    transactionId,
    validationCode,
    successful: validationCode === 0,
    blockNumber: blockNumber.toString(),
    source,
  });
}

export function createFabricAuditGateway({ topology, writerGateway, verifierGateway, closeTransport = () => {} } = {}) {
  if (!writerGateway || typeof writerGateway.getNetwork !== "function") {
    throw new TypeError("A Fabric Gateway writer session is required.");
  }
  if (!verifierGateway || typeof verifierGateway.getNetwork !== "function") {
    throw new TypeError("A Fabric Gateway verifier session is required.");
  }
  if (typeof closeTransport !== "function") throw new TypeError("A transport close function is required.");
  const channels = buildChannelMap(topology);
  const writerContracts = new Map();
  const verifierContracts = new Map();
  const verifierSystemContracts = new Map();
  let closed = false;

  function channelForTenant(tenantId) {
    if (closed) fail("GATEWAY_CLOSED");
    if (!TENANT_ID.test(tenantId ?? "")) throw new TypeError("tenantId must be a canonical tenant identifier.");
    const channelName = channels.get(tenantId);
    if (!channelName) fail("TENANT_CHANNEL_UNAVAILABLE");
    return channelName;
  }

  function contractFor(gateway, cache, channelName, chaincodeName = FABRIC_AUDIT_GATEWAY_POLICY.chaincodeName,
    contractName = FABRIC_AUDIT_GATEWAY_POLICY.contractName) {
    let contract = cache.get(channelName);
    if (!contract) {
      contract = gateway
        .getNetwork(channelName)
        .getContract(chaincodeName, contractName);
      cache.set(channelName, contract);
    }
    return contract;
  }

  function systemContractFor(channelName) {
    let contract = verifierSystemContracts.get(channelName);
    if (!contract) {
      contract = verifierGateway.getNetwork(channelName).getContract("qscc");
      verifierSystemContracts.set(channelName, contract);
    }
    return contract;
  }

  async function submitCommitment(request) {
    assertExactFields(request, SUBMIT_FIELDS, "submission");
    const channelName = channelForTenant(request.tenantId);
    assertAuditLedgerValue(request.ledgerValue);
    const ledgerKey = expectedLedgerKey(request.ledgerValue);
    let response;
    let submitted;
    try {
      submitted = await contractFor(writerGateway, writerContracts, channelName)
        .submitAsync("CommitCommitment", { arguments: [JSON.stringify(request.ledgerValue)] });
      response = parseJsonResult(submitted.getResult(), "SUBMISSION_RESULT_INVALID");
    } catch (error) {
      if (error instanceof FabricAuditGatewayError) throw error;
      fail("SUBMISSION_FAILED", error);
    }
    const fields = Object.keys(response).sort();
    if (fields.length !== 2
      || fields[0] !== "ledgerKey"
      || fields[1] !== "status"
      || response.ledgerKey !== ledgerKey
      || !RESPONSE_STATUS.has(response.status)) {
      fail("SUBMISSION_RESULT_INVALID");
    }
    const transactionId = submitted.getTransactionId();
    if (!SHA256.test(transactionId ?? "")) fail("TRANSACTION_ID_INVALID");
    let commitStatusPromise;
    return Object.freeze({
      ledgerKey,
      status: response.status,
      transactionId,
      waitForCommit() {
        commitStatusPromise ??= submitted.getStatus()
          .then((status) => validatedCommitStatus(status, "gateway-status", transactionId))
          .catch((error) => {
            if (error instanceof FabricAuditGatewayError) throw error;
            fail("COMMIT_STATUS_UNAVAILABLE", error);
          });
        return commitStatusPromise;
      },
    });
  }

  async function queryTransactionStatus(request) {
    assertExactFields(request, STATUS_FIELDS, "transaction status query");
    const channelName = channelForTenant(request.tenantId);
    if (!SHA256.test(request.transactionId ?? "")) {
      throw new TypeError("transactionId must be a lowercase SHA-256 digest.");
    }
    try {
      const contract = systemContractFor(channelName);
      const [processedBytes, blockBytes] = await Promise.all([
        contract.evaluateTransaction("GetTransactionByID", channelName, request.transactionId),
        contract.evaluateTransaction("GetBlockByTxID", channelName, request.transactionId),
      ]);
      const processed = fabricProtos.peer.ProcessedTransaction.deserializeBinary(processedBytes);
      const block = fabricProtos.common.Block.deserializeBinary(blockBytes);
      const blockNumber = block.getHeader()?.getNumber();
      return validatedCommitStatus({
        transactionId: request.transactionId,
        validationCode: processed.getValidationcode(),
        blockNumber,
      }, "qscc", request.transactionId);
    } catch (error) {
      if (error instanceof FabricAuditGatewayError) throw error;
      fail("TRANSACTION_STATUS_QUERY_FAILED", error);
    }
  }

  async function readCommitment(request) {
    assertExactFields(request, READ_FIELDS, "query");
    const channelName = channelForTenant(request.tenantId);
    if (typeof request.recordType !== "string" || request.recordType.length === 0) {
      throw new TypeError("recordType is required.");
    }
    if (!SHA256.test(request.eventKeyHashSha256 ?? "")) {
      throw new TypeError("eventKeyHashSha256 must be a lowercase SHA-256 digest.");
    }
    let result;
    try {
      result = await contractFor(verifierGateway, verifierContracts, channelName)
        .evaluateTransaction("ReadCommitment", request.recordType, request.eventKeyHashSha256);
    } catch (error) {
      fail("QUERY_FAILED", error);
    }
    const ledgerValue = parseJsonResult(result, "QUERY_RESULT_INVALID");
    try {
      assertAuditLedgerValue(ledgerValue);
    } catch (error) {
      fail("QUERY_RESULT_INVALID", error);
    }
    if (ledgerValue.recordType !== request.recordType
      || ledgerValue.eventKeyHashSha256 !== request.eventKeyHashSha256) {
      fail("QUERY_RESULT_INVALID");
    }
    return Object.freeze({ ...ledgerValue });
  }

  function close() {
    if (closed) return;
    closed = true;
    writerContracts.clear();
    verifierContracts.clear();
    verifierSystemContracts.clear();
    try {
      writerGateway.close();
    } finally {
      try {
        verifierGateway.close();
      } finally {
        closeTransport();
      }
    }
  }

  return Object.freeze({
    policy: FABRIC_AUDIT_GATEWAY_POLICY,
    submitCommitment,
    queryTransactionStatus,
    readCommitment,
    close,
  });
}

async function readSingleFile(directory, label) {
  let entries;
  try {
    entries = (await readdir(directory, { withFileTypes: true })).filter((entry) => entry.isFile());
  } catch (error) {
    fail("IDENTITY_MATERIAL_UNAVAILABLE", error);
  }
  if (entries.length !== 1) fail("IDENTITY_MATERIAL_INVALID");
  try {
    return await readFile(resolve(directory, entries[0].name));
  } catch (error) {
    fail(`${label}_UNAVAILABLE`, error);
  }
}

async function loadSigningIdentity(mspDirectory) {
  const [credentials, privateKeyPem] = await Promise.all([
    readSingleFile(resolve(mspDirectory, "signcerts"), "SIGNCERT"),
    readSingleFile(resolve(mspDirectory, "keystore"), "PRIVATE_KEY"),
  ]);
  let privateKey;
  try {
    privateKey = createPrivateKey(privateKeyPem);
  } catch (error) {
    fail("IDENTITY_MATERIAL_INVALID", error);
  } finally {
    privateKeyPem.fill(0);
  }
  return {
    identity: { mspId: FABRIC_AUDIT_GATEWAY_POLICY.mspId, credentials },
    signer: signers.newPrivateKeySigner(privateKey),
  };
}

function parseTimeout(value) {
  const timeout = Number(value ?? FABRIC_AUDIT_GATEWAY_POLICY.requestTimeoutMilliseconds);
  if (!Number.isSafeInteger(timeout) || timeout < 1_000 || timeout > 60_000) {
    throw new TypeError("FABRIC_GATEWAY_REQUEST_TIMEOUT_MS must be between 1000 and 60000.");
  }
  return timeout;
}

function configuredPath(repositoryRoot, value, fallback) {
  const selected = value || fallback;
  if (typeof selected !== "string" || selected.length === 0 || selected.includes("\0")) {
    throw new TypeError("Fabric gateway credential paths must be non-empty filesystem paths.");
  }
  return resolve(repositoryRoot, selected);
}

export async function connectFabricAuditGatewayFromEnvironment({
  environment = process.env,
  repositoryRoot = resolve(import.meta.dirname, "../../.."),
} = {}) {
  const endpoint = environment.FABRIC_GATEWAY_ENDPOINT ?? "127.0.0.1:17051";
  const serverName = environment.FABRIC_GATEWAY_SERVER_NAME ?? "peer0.platform.audit.tenant-trust.test";
  if (!ENDPOINT.test(endpoint) || Number(endpoint.slice(endpoint.lastIndexOf(":") + 1)) > 65_535) {
    throw new TypeError("FABRIC_GATEWAY_ENDPOINT must be a valid host and TCP port.");
  }
  if (!SERVER_NAME.test(serverName)) throw new TypeError("FABRIC_GATEWAY_SERVER_NAME must be a DNS name.");
  const timeout = parseTimeout(environment.FABRIC_GATEWAY_REQUEST_TIMEOUT_MS);
  const platformRoot = "runtime/fabric/organizations/peerOrganizations/platform.audit.tenant-trust.test";
  const topologyPath = configuredPath(repositoryRoot, environment.FABRIC_GATEWAY_TOPOLOGY_PATH, "config/fabric-topology.json");
  const tlsRootPath = configuredPath(
    repositoryRoot,
    environment.FABRIC_GATEWAY_TLS_ROOT_CERT_PATH,
    `${platformRoot}/peers/peer0.platform.audit.tenant-trust.test/tls/ca.crt`,
  );
  const writerMspPath = configuredPath(
    repositoryRoot,
    environment.FABRIC_GATEWAY_WRITER_MSP_PATH,
    `${platformRoot}/users/audit-writer@platform.audit.tenant-trust.test/msp`,
  );
  const verifierMspPath = configuredPath(
    repositoryRoot,
    environment.FABRIC_GATEWAY_VERIFIER_MSP_PATH,
    `${platformRoot}/users/audit-verifier@platform.audit.tenant-trust.test/msp`,
  );

  let topology;
  let tlsRootCertificate;
  try {
    [topology, tlsRootCertificate] = await Promise.all([
      readFile(topologyPath, "utf8").then(JSON.parse),
      readFile(tlsRootPath),
    ]);
  } catch (error) {
    fail("GATEWAY_CONFIGURATION_UNAVAILABLE", error);
  }
  const [writer, verifier] = await Promise.all([
    loadSigningIdentity(writerMspPath),
    loadSigningIdentity(verifierMspPath),
  ]);
  const client = new grpc.Client(endpoint, grpc.credentials.createSsl(tlsRootCertificate), {
    "grpc.ssl_target_name_override": serverName,
    "grpc.default_authority": serverName,
  });
  const callOptions = () => ({ deadline: Date.now() + timeout });
  let writerGateway;
  let verifierGateway;
  try {
    writerGateway = connect({
      client,
      identity: writer.identity,
      signer: writer.signer,
      hash: hash.sha256,
      evaluateOptions: callOptions,
      endorseOptions: callOptions,
      submitOptions: callOptions,
      commitStatusOptions: callOptions,
    });
    verifierGateway = connect({
      client,
      identity: verifier.identity,
      signer: verifier.signer,
      hash: hash.sha256,
      evaluateOptions: callOptions,
      endorseOptions: callOptions,
      submitOptions: callOptions,
      commitStatusOptions: callOptions,
    });
    return createFabricAuditGateway({
      topology,
      writerGateway,
      verifierGateway,
      closeTransport: () => client.close(),
    });
  } catch (error) {
    writerGateway?.close();
    verifierGateway?.close();
    client.close();
    if (error instanceof FabricAuditGatewayError) throw error;
    fail("GATEWAY_CONNECTION_FAILED", error);
  }
}
