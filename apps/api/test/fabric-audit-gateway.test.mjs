import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import fabricProtos from "@hyperledger/fabric-protos";
import {
  FABRIC_AUDIT_GATEWAY_POLICY,
  FabricAuditGatewayError,
  createFabricAuditGateway,
} from "../src/fabric-audit-gateway.mjs";

const topology = JSON.parse(await readFile(new URL("../../../config/fabric-topology.json", import.meta.url), "utf8"));
const alphaTenantId = "tnt_018f1234-5678-7abc-8def-0123456789ab";
const betaTenantId = "tnt_018f1234-5678-7abc-8def-0123456789ac";
const hash = (character) => character.repeat(64);
const transactionId = hash("c");
const ledgerValue = Object.freeze({
  canonicalizationProfile: "tenant-trust-audit-commitment-json-v1",
  commitmentHashSha256: hash("b"),
  digestAlgorithm: "sha256",
  eventKeyHashSha256: hash("a"),
  recordType: "trust-transition",
  schemaVersion: "1.0.0",
});

function gatewayFixture() {
  const calls = [];
  let writerClosed = 0;
  let verifierClosed = 0;
  let transportClosed = 0;
  const contract = (mode, channelName, chaincodeName) => ({
    async submitAsync(name, options) {
      calls.push({ mode, channelName, operation: "submit", name, options });
      return {
        getResult: () => Buffer.from(JSON.stringify({
          ledgerKey: `audit~${ledgerValue.recordType}~${ledgerValue.eventKeyHashSha256}`,
          status: "created",
        })),
        getTransactionId: () => transactionId,
        getStatus: async () => ({ transactionId, code: 0, successful: true, blockNumber: 42n }),
      };
    },
    async evaluateTransaction(name, recordType, eventKeyHashSha256) {
      calls.push({ mode, channelName, operation: "evaluate", name, recordType, eventKeyHashSha256 });
      if (chaincodeName === "qscc" && name === "GetTransactionByID") {
        const processed = new fabricProtos.peer.ProcessedTransaction();
        processed.setValidationcode(0);
        return processed.serializeBinary();
      }
      if (chaincodeName === "qscc" && name === "GetBlockByTxID") {
        const header = new fabricProtos.common.BlockHeader();
        header.setNumber(42);
        const block = new fabricProtos.common.Block();
        block.setHeader(header);
        return block.serializeBinary();
      }
      return Buffer.from(JSON.stringify(ledgerValue));
    },
  });
  const writerGateway = {
    getNetwork(channelName) {
      return { getContract: (chaincodeName, contractName) => {
        calls.push({ mode: "writer", channelName, operation: "contract", chaincodeName, contractName });
        return contract("writer", channelName, chaincodeName);
      } };
    },
    close() { writerClosed += 1; },
  };
  const verifierGateway = {
    getNetwork(channelName) {
      return { getContract: (chaincodeName, contractName) => {
        calls.push({ mode: "verifier", channelName, operation: "contract", chaincodeName, contractName });
        return contract("verifier", channelName, chaincodeName);
      } };
    },
    close() { verifierClosed += 1; },
  };
  const client = createFabricAuditGateway({
    topology,
    writerGateway,
    verifierGateway,
    closeTransport() { transportClosed += 1; },
  });
  return {
    client,
    calls,
    closeCounts: () => ({ writerClosed, verifierClosed, transportClosed }),
  };
}

test("submissions derive the tenant channel and use only the writer session", async () => {
  const fixture = gatewayFixture();
  const result = await fixture.client.submitCommitment({ tenantId: alphaTenantId, ledgerValue });

  assert.equal(result.ledgerKey, `audit~trust-transition~${hash("a")}`);
  assert.equal(result.status, "created");
  assert.equal(result.transactionId, transactionId);
  assert.deepEqual(await result.waitForCommit(), { transactionId, validationCode: 0, successful: true,
    blockNumber: "42", source: "gateway-status" });
  assert.deepEqual(fixture.calls[0], {
    mode: "writer",
    channelName: "tt-audit-alpha-v1",
    operation: "contract",
    chaincodeName: FABRIC_AUDIT_GATEWAY_POLICY.chaincodeName,
    contractName: FABRIC_AUDIT_GATEWAY_POLICY.contractName,
  });
  assert.equal(fixture.calls[1].mode, "writer");
  assert.equal(fixture.calls.some(({ mode }) => mode === "verifier"), false);
});

test("restart reconciliation reads transaction validation and block through QSCC", async () => {
  const fixture = gatewayFixture();
  assert.deepEqual(await fixture.client.queryTransactionStatus({ tenantId: alphaTenantId, transactionId }), {
    transactionId, validationCode: 0, successful: true, blockNumber: "42", source: "qscc",
  });
  assert.equal(fixture.calls[0].chaincodeName, "qscc");
  assert.equal(fixture.calls.filter(({ operation }) => operation === "evaluate").length, 2);
});

test("queries derive the other tenant channel and use only the verifier session", async () => {
  const fixture = gatewayFixture();
  const result = await fixture.client.readCommitment({
    tenantId: betaTenantId,
    recordType: ledgerValue.recordType,
    eventKeyHashSha256: ledgerValue.eventKeyHashSha256,
  });

  assert.deepEqual(result, ledgerValue);
  assert.equal(fixture.calls[0].mode, "verifier");
  assert.equal(fixture.calls[0].channelName, "tt-audit-beta-v1");
  assert.equal(fixture.calls[1].operation, "evaluate");
  assert.equal(fixture.calls.some(({ mode }) => mode === "writer"), false);
});

test("callers cannot select a channel or add ledger credential material", async () => {
  const fixture = gatewayFixture();
  await assert.rejects(
    fixture.client.submitCommitment({
      tenantId: alphaTenantId,
      ledgerValue,
      channelName: "tt-audit-beta-v1",
    }),
    /unsupported fields/u,
  );
  await assert.rejects(
    fixture.client.readCommitment({
      tenantId: alphaTenantId,
      recordType: ledgerValue.recordType,
      eventKeyHashSha256: ledgerValue.eventKeyHashSha256,
      privateKey: "not-accepted",
    }),
    /unsupported fields/u,
  );
  assert.equal(fixture.calls.length, 0);
});

test("unknown tenants fail before any Fabric operation", async () => {
  const fixture = gatewayFixture();
  await assert.rejects(
    fixture.client.submitCommitment({
      tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ad",
      ledgerValue,
    }),
    (error) => error instanceof FabricAuditGatewayError && error.reasonCode === "TENANT_CHANNEL_UNAVAILABLE",
  );
  assert.equal(fixture.calls.length, 0);
});

test("invalid commitments and mismatched ledger results fail closed", async () => {
  const fixture = gatewayFixture();
  await assert.rejects(
    fixture.client.submitCommitment({
      tenantId: alphaTenantId,
      ledgerValue: { ...ledgerValue, tenantId: alphaTenantId },
    }),
    /unapproved public fields/u,
  );
  await assert.rejects(
    fixture.client.readCommitment({
      tenantId: alphaTenantId,
      recordType: "access-decision",
      eventKeyHashSha256: ledgerValue.eventKeyHashSha256,
    }),
    (error) => error instanceof FabricAuditGatewayError && error.reasonCode === "QUERY_RESULT_INVALID",
  );
});

test("the public client surface contains operations and policy, never sessions or credentials", () => {
  const fixture = gatewayFixture();
  assert.deepEqual(Object.keys(fixture.client).sort(), ["close", "policy", "queryTransactionStatus", "readCommitment", "submitCommitment"]);
  assert.equal(JSON.stringify(fixture.client).includes("PRIVATE KEY"), false);
  assert.equal(JSON.stringify(fixture.client).includes("credentials"), false);

  fixture.client.close();
  fixture.client.close();
  assert.deepEqual(fixture.closeCounts(), { writerClosed: 1, verifierClosed: 1, transportClosed: 1 });
});
