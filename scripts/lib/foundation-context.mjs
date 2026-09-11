import { readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

export const repositoryRoot = resolve(import.meta.dirname, "../..");
const configuredEnvironmentFile = process.env.TENANT_TRUST_ENV_FILE || ".env";
export const environmentFile = isAbsolute(configuredEnvironmentFile)
  ? configuredEnvironmentFile
  : resolve(repositoryRoot, configuredEnvironmentFile);

export const environment = Object.fromEntries(
  readFileSync(environmentFile, "utf8")
    .split(/\r?\n/u)
    .filter((line) => line && !line.startsWith("#") && line.includes("="))
    .map((line) => {
      const separator = line.indexOf("=");
      return [line.slice(0, separator), line.slice(separator + 1)];
    }),
);

export const composeArgs = ["compose", "--env-file", environmentFile, "-f", "infra/compose/compose.yaml"];
if (process.env.TENANT_TRUST_COMPOSE_PROJECT) {
  composeArgs.push("--project-name", process.env.TENANT_TRUST_COMPOSE_PROJECT);
}
