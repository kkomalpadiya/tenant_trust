import { spawnSync } from "node:child_process";
import { environmentFile, repositoryRoot } from "./lib/foundation-context.mjs";

const result = spawnSync(
  "docker",
  ["compose", "--env-file", environmentFile, "-f", "infra/fabric/compose.yaml",
    "--profile", "tools", "run", "--rm", "--no-deps", "ledger-privacy-verify"],
  { cwd: repositoryRoot, encoding: "utf8", maxBuffer: 4 * 1024 * 1024, windowsHide: true,timeout: 180_000 },
);
if (result.error || result.status !== 0) {
  const detail = (result.stderr || result.stdout || result.error?.message || "unknown failure").trim();
  throw new Error(`Fabric ledger privacy verification failed:\n${detail}`);
}
if (result.stdout.trim()) console.log(result.stdout.trim());
if (result.stderr.trim()) console.error(result.stderr.trim());
