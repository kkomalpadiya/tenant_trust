import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { Pool } from "pg";
import {
  createPostgresSecurityActionAuditRepository,
  createSecurityActionAuditProjector,
} from "../services/audit/src/index.mjs";
import { environment, repositoryRoot } from "./lib/foundation-context.mjs";

const pollIntervalMilliseconds = Number(
  environment.SECURITY_ACTION_AUDIT_POLL_INTERVAL_MS ?? 1_000,
);
if (!Number.isSafeInteger(pollIntervalMilliseconds)
    || pollIntervalMilliseconds < 100
    || pollIntervalMilliseconds > 60_000) {
  throw new TypeError("SECURITY_ACTION_AUDIT_POLL_INTERVAL_MS must be between 100 and 60000.");
}

const topologyPath = resolve(
  repositoryRoot,
  environment.FABRIC_GATEWAY_TOPOLOGY_PATH ?? "config/fabric-topology.json",
);
const topology = JSON.parse(await readFile(topologyPath, "utf8"));
if (topology?.schemaVersion !== "1.0.0" || !Array.isArray(topology.channels)) {
  throw new TypeError("A supported Fabric tenant-channel topology is required.");
}
const channels = new Map();
for (const channel of topology.channels) {
  if (typeof channel?.tenantId !== "string" || typeof channel?.name !== "string"
      || channels.has(channel.tenantId)) {
    throw new TypeError("Fabric topology must map every tenant to one audit channel.");
  }
  channels.set(channel.tenantId, channel.name);
}

const pool = new Pool({
  host: "127.0.0.1",
  port: Number(environment.POSTGRES_HOST_PORT),
  database: environment.POSTGRES_DB,
  user: environment.POSTGRES_USER,
  password: environment.POSTGRES_PASSWORD,
  max: 2,
  application_name: "security-action-audit-projector",
});

async function projectorQuery(text, values) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL ROLE tenant_trust_security_action_audit_projector");
    const result = await client.query(text, values);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

const repository = createPostgresSecurityActionAuditRepository({ query: projectorQuery });
const projector = createSecurityActionAuditProjector({
  repository,
  channelForTenant: async (tenantId) => channels.get(tenantId),
});
const stop = new AbortController();
for (const signalName of ["SIGINT", "SIGTERM"]) {
  process.once(signalName, () => stop.abort());
}

console.log("Security-action audit projector started.");
try {
  while (!stop.signal.aborted) {
    try {
      const result = await projector.runOnce();
      if (result.status === "idle") {
        await delay(pollIntervalMilliseconds, undefined, { signal: stop.signal });
      } else {
        console.log(`Queued ${result.eventType} ${result.eventId} for action ${result.actionId}.`);
      }
    } catch (error) {
      if (stop.signal.aborted) break;
      console.error("Security-action audit projection failed; the immutable source remains pending.");
      await delay(pollIntervalMilliseconds, undefined, { signal: stop.signal });
    }
  }
} catch (error) {
  if (!stop.signal.aborted) throw error;
} finally {
  await pool.end();
  console.log("Security-action audit projector stopped.");
}
