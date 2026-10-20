import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { environment, repositoryRoot } from "./lib/foundation-context.mjs";

function checkFixture(name) {
  const fixturePath = resolve(repositoryRoot, "tests", "fixtures", "policy-bundles", name);
  return spawnSync(
    "docker",
    [
      "run",
      "--rm",
      "--volume",
      `${fixturePath}:/bundle:ro`,
      environment.OPA_IMAGE,
      "check",
      "--v1-compatible",
      "/bundle",
    ],
    { cwd: repositoryRoot, encoding: "utf8", maxBuffer: 1024 * 1024 },
  );
}

const valid = checkFixture("valid");
if (valid.status !== 0) {
  const detail = (valid.stderr || valid.stdout || valid.error?.message || "").trim();
  throw new Error(`Pinned OPA rejected the valid policy bundle fixture${detail ? `:\n${detail}` : ""}`);
}

const invalid = checkFixture("invalid");
if (invalid.status === 0) {
  throw new Error("Pinned OPA accepted the deliberately invalid policy bundle fixture.");
}

console.log("Pinned OPA accepted the valid Rego v1 bundle and rejected the invalid bundle.");
