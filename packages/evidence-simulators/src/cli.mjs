import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import {
  generateAdversarialEvidenceFixtureSet,
  generateDeterministicDemoEvidenceSet,
} from "./index.mjs";

function parseArguments(args) {
  const options = { tenantAlias: "alpha", observedAt: "2026-10-05T08:00:00.000Z", sourceSequence: 1 };
  let suite = "baseline";
  let outputPath;
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!value) throw new Error(`Missing value for ${flag ?? "argument"}.`);
    if (flag === "--tenant") options.tenantAlias = value;
    else if (flag === "--observed-at") options.observedAt = value;
    else if (flag === "--sequence") options.sourceSequence = Number(value);
    else if (flag === "--flood-count") options.floodEventCount = Number(value);
    else if (flag === "--suite") suite = value;
    else if (flag === "--output") outputPath = resolve(value);
    else throw new Error(`Unknown option: ${flag}`);
  }
  if (!["baseline", "adversarial"].includes(suite)) throw new Error(`Unknown fixture suite: ${suite}`);
  return { options, outputPath, suite };
}

const { options, outputPath, suite } = parseArguments(process.argv.slice(2));
const generated = suite === "adversarial"
  ? generateAdversarialEvidenceFixtureSet(options)
  : generateDeterministicDemoEvidenceSet(options);
const fixture = `${JSON.stringify(generated, null, 2)}\n`;
if (outputPath) {
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, fixture, { encoding: "utf8", flag: "wx" });
  console.log(`Wrote deterministic ${suite} synthetic evidence fixtures to ${outputPath}`);
} else {
  process.stdout.write(fixture);
}
