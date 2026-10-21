import { Pool } from "pg";
import { createPostgresAuditOutboxWorkerRepository } from "../services/audit/src/index.mjs";
import { environment } from "./lib/foundation-context.mjs";

const pool = new Pool({ host: "127.0.0.1", port: Number(environment.POSTGRES_HOST_PORT),
  database: environment.POSTGRES_DB, user: environment.POSTGRES_USER, password: environment.POSTGRES_PASSWORD,
  max: 2, application_name: "audit-outbox-status" });

async function restrictedQuery(text, values) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL ROLE tenant_trust_audit_outbox_worker");
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
  const status = await createPostgresAuditOutboxWorkerRepository({ query: restrictedQuery }).deliveryStatus();
  console.log("Audit commitment delivery summary");
  console.table(status.summary);
  console.log("Uncommitted audit gaps");
  if (status.gaps.length === 0) console.log("None.");
  else console.table(status.gaps);
} finally {
  await pool.end();
}
