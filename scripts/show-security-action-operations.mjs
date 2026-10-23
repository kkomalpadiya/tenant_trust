import { Pool } from "pg";
import {
  createPostgresSecurityActionOperationsRepository,
  createSecurityActionOperationsMonitor,
} from "../services/orchestrator/src/index.mjs";
import { environment } from "./lib/foundation-context.mjs";

const recoverExpired = process.argv.slice(2).includes("--recover-expired");
const workerId = environment.SECURITY_ACTION_WORKER_ID ?? "orchestrator.local-1";
const pool = new Pool({
  host: "127.0.0.1",
  port: Number(environment.POSTGRES_HOST_PORT),
  database: environment.POSTGRES_DB,
  user: environment.POSTGRES_USER,
  password: environment.POSTGRES_PASSWORD,
  max: 2,
  application_name: recoverExpired ? "security-action-recovery" : "security-action-status",
});

async function operatorQuery(text, values) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL ROLE tenant_trust_security_action_operator");
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

try {
  const repository = createPostgresSecurityActionOperationsRepository({ query: operatorQuery });
  const monitor = createSecurityActionOperationsMonitor({ repository });
  const report = recoverExpired
    ? await monitor.recoverOnStartup({ workerId, limit: 500 })
    : await monitor.inspect({ limit: 500 });
  if (report.recovery) {
    console.log(`Recovered ${report.recovery.recoveredCount} expired security-action lease(s).`);
  }
  console.log(`Security-action operations status: ${report.status}.`);
  console.table(report.counts);
  if (report.issues.length === 0) console.log("No active security-action operational issues.");
  else console.table(report.issues);
  if (report.status === "critical") process.exitCode = 2;
} finally {
  await pool.end();
}
