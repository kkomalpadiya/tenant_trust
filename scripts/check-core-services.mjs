import { spawnSync } from "node:child_process";
import { AuthorizationError, connect } from "@nats-io/transport-node";
import { composeArgs, environment, repositoryRoot } from "./lib/foundation-context.mjs";

const psql = ["exec", "-T", "postgres", "psql", "-U", environment.POSTGRES_USER, "-d", environment.POSTGRES_DB, "-Atqc"];

function run(args, label) {
  const result = spawnSync("docker", [...composeArgs, ...args], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout).trim();
    throw new Error(`${label} failed${detail ? `: ${detail}` : ""}`);
  }
  return result.stdout.trim();
}

const checks = [
  {
    label: "PostgreSQL accepts authenticated queries",
    args: [...psql, "SELECT 1"],
    expected: "1",
  },
  {
    label: "Foundation migration is recorded",
    args: [...psql, "SELECT count(*) FROM platform.schema_migrations"],
    expected: "1",
  },
  {
    label: "Identity, trust and audit schemas exist",
    args: [...psql, "SELECT count(*) FROM information_schema.schemata WHERE schema_name IN ('identity','trust','audit')"],
    expected: "3",
  },
  {
    label: "Redis accepts authenticated commands",
    args: ["exec", "-T", "redis", "redis-cli", "--no-auth-warning", "ping"],
    expected: "PONG",
  },
  {
    label: "Redis rejects unauthenticated commands",
    args: ["exec", "-T", "redis", "env", "-u", "REDISCLI_AUTH", "redis-cli", "ping"],
    expected: "NOAUTH Authentication required.",
  },
  {
    label: "Redis append-only persistence is enabled",
    args: ["exec", "-T", "redis", "redis-cli", "--no-auth-warning", "CONFIG", "GET", "appendonly"],
    expected: "appendonly\nyes",
  },
  {
    label: "Redis eviction is disabled for durable state",
    args: ["exec", "-T", "redis", "redis-cli", "--no-auth-warning", "CONFIG", "GET", "maxmemory-policy"],
    expected: "maxmemory-policy\nnoeviction",
  },
];

let failures = 0;
for (const check of checks) {
  try {
    const actual = run(check.args, check.label).replaceAll("\r", "");
    if (actual !== check.expected) {
      throw new Error(`expected ${JSON.stringify(check.expected)}, received ${JSON.stringify(actual)}`);
    }
    console.log(`PASS ${check.label}`);
  } catch (error) {
    failures += 1;
    console.error(`FAIL ${error.message}`);
  }
}

try {
  const connection = await connect({
    servers: `nats://127.0.0.1:${environment.NATS_HOST_PORT}`,
    user: environment.NATS_USER,
    pass: environment.NATS_PASSWORD,
    name: "tenant-trust-core-check",
    timeout: 3_000,
  });
  await connection.close();
  console.log("PASS NATS accepts authenticated connections");
} catch (error) {
  failures += 1;
  console.error(`FAIL NATS authenticated connection failed: ${error.message}`);
}

try {
  const unauthenticated = await connect({
    servers: `nats://127.0.0.1:${environment.NATS_HOST_PORT}`,
    name: "tenant-trust-unauthenticated-check",
    timeout: 3_000,
  });
  await unauthenticated.close();
  failures += 1;
  console.error("FAIL NATS accepted an unauthenticated connection");
} catch (error) {
  if (error instanceof AuthorizationError) {
    console.log("PASS NATS rejects unauthenticated connections");
  } else {
    failures += 1;
    console.error(`FAIL NATS unauthenticated check failed unexpectedly: ${error.message}`);
  }
}

if (failures > 0) process.exit(1);
console.log("Core service checks passed.");
