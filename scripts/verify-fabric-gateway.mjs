import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  FabricAuditGatewayError,
  connectFabricAuditGatewayFromEnvironment,
} from "../apps/api/src/fabric-audit-gateway.mjs";

const topology = JSON.parse(await readFile(new URL("../config/fabric-topology.json", import.meta.url), "utf8"));
const apiSource = await readFile(new URL("../apps/api/src/app.mjs", import.meta.url), "utf8");
const digest = (value) => createHash("sha256").update(value).digest("hex");
const client = await connectFabricAuditGatewayFromEnvironment();

try {
  assert.equal(apiSource.includes("FABRIC_GATEWAY_WRITER_MSP_PATH"), false);
  assert.equal(apiSource.includes("FABRIC_GATEWAY_VERIFIER_MSP_PATH"), false);
  assert.equal(apiSource.includes("/v1/audit"), false);
  assert.deepEqual(Object.keys(client).sort(), ["close", "policy", "queryTransactionStatus", "readCommitment", "submitCommitment"]);
  assert.equal(JSON.stringify(client).includes("PRIVATE KEY"), false);

  for (const tenant of topology.tenants) {
    const suffix = tenant.slug.replace("tenant-", "");
    const ledgerValue = Object.freeze({
      canonicalizationProfile: "tenant-trust-audit-commitment-json-v1",
      commitmentHashSha256: digest(`tenant-trust:t8.5:${suffix}:commitment:v1`),
      digestAlgorithm: "sha256",
      eventKeyHashSha256: digest(`tenant-trust:t8.5:${suffix}:event:v1`),
      recordType: "trust-transition",
      schemaVersion: "1.0.0",
    });
    const first = await client.submitCommitment({ tenantId: tenant.tenantId, ledgerValue });
    assert(new Set(["created", "duplicate"]).has(first.status));
    const firstStatus = await first.waitForCommit();
    assert.equal(firstStatus.successful, true);
    assert.equal(firstStatus.transactionId, first.transactionId);
    assert.deepEqual(await client.queryTransactionStatus({ tenantId: tenant.tenantId, transactionId: first.transactionId }), {
      ...firstStatus,
      source: "qscc",
    });
    const retry = await client.submitCommitment({ tenantId: tenant.tenantId, ledgerValue });
    assert.equal(retry.status, "duplicate");
    assert.equal((await retry.waitForCommit()).successful, true);
    assert.deepEqual(
      await client.readCommitment({
        tenantId: tenant.tenantId,
        recordType: ledgerValue.recordType,
        eventKeyHashSha256: ledgerValue.eventKeyHashSha256,
      }),
      ledgerValue,
    );
  }

  await assert.rejects(
    client.readCommitment({
      tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ad",
      recordType: "trust-transition",
      eventKeyHashSha256: digest("tenant-trust:t8.5:unknown"),
    }),
    (error) => error instanceof FabricAuditGatewayError && error.reasonCode === "TENANT_CHANNEL_UNAVAILABLE",
  );
  console.log("Fabric Gateway verified: separated service identities submitted and queried both tenant channels without exposing ledger credentials to API clients.");
} finally {
  client.close();
}
