import { setTimeout as delay } from "node:timers/promises";
import { Pool } from "pg";
import { connectFabricAuditGatewayFromEnvironment } from "../apps/api/src/fabric-audit-gateway.mjs";
import {
  createAuditOutboxWorker,
  createPostgresAuditOutboxWorkerRepository,
} from "../services/audit/src/index.mjs";
import { environment, repositoryRoot } from "./lib/foundation-context.mjs";

const workerId = environment.AUDIT_OUTBOX_WORKER_ID ?? "audit-worker.local-1";
const pollIntervalMilliseconds = Number(environment.AUDIT_OUTBOX_POLL_INTERVAL_MS ?? 1_000);
if (!Number.isSafeInteger(pollIntervalMilliseconds)
    || pollIntervalMilliseconds < 100
    || pollIntervalMilliseconds > 60_000) {
  throw new TypeError("AUDIT_OUTBOX_POLL_INTERVAL_MS must be between 100 and 60000.");
}

const pool = new Pool({
  host: "127.0.0.1",
  port: Number(environment.POSTGRES_HOST_PORT),
  database: environment.POSTGRES_DB,
  user: environment.POSTGRES_USER,
  password: environment.POSTGRES_PASSWORD,
  max: 2,
  application_name: workerId,
});

async function workerQuery(text, values) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL ROLE tenant_trust_audit_outbox_worker");
    const result = await client.query(text, values);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {
      // Preserve the original database failure; an abandoned claim is lease-recovered.
    }
    throw error;
  } finally {
    client.release();
  }
}

const gateway = await connectFabricAuditGatewayFromEnvironment({
  environment: { ...process.env, ...environment },
  repositoryRoot,
});
const outbox = createPostgresAuditOutboxWorkerRepository({ query: workerQuery });
const worker = createAuditOutboxWorker({ workerId, outbox, gateway });
const stop = new AbortController();

for (const signalName of ["SIGINT", "SIGTERM"]) {
  process.once(signalName, () => stop.abort());
}

console.log(`Audit outbox worker started as ${workerId}.`);
try {
  while (!stop.signal.aborted) {
    try {
      const result = await worker.runOnce();
      if (result.status === "committed") {
        console.log(`Committed audit event ${result.eventId} in block ${result.blockNumber} (${result.confirmationSource}).`);
      } else if (result.status === "confirmation-pending") {
        console.warn(`Audit event ${result.eventId} awaits reconciliation (${result.failureCode}).`);
      } else if (result.status === "failed") {
        console.warn(`Audit event ${result.eventId} failed and is scheduled for retry (${result.failureCode ?? `validation-${result.validationCode}`}).`);
      } else {
        await delay(pollIntervalMilliseconds, undefined, { signal: stop.signal });
      }
    } catch (error) {
      if (stop.signal.aborted) break;
      console.error("Audit outbox worker iteration failed; the durable claim will be recovered if necessary.");
      await delay(pollIntervalMilliseconds, undefined, { signal: stop.signal });
    }
  }
} catch (error) {
  if (!stop.signal.aborted) throw error;
} finally {
  gateway.close();
  await pool.end();
  console.log("Audit outbox worker stopped.");
}
