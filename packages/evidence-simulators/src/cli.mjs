import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { generateDeterministicDemoEvidenceSet } from "./index.mjs";

function parseArguments(args) {
  const options = { tenantAlias: "alpha", observedAt: "2026-10-05T08:00:00.000Z", sourceSequence: 1 };
  let outputPath;
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!value) throw new Error(`Missing value for ${flag ?? "argument"}.`);
    if (flag === "--tenant") options.tenantAlias = value;
    else if (flag === "--observed-at") options.observedAt = value;
    else if (flag === "--sequence") options.sourceSequence = Number(value);
    else if (flag === "--output") outputPath = resolve(value);
    else throw new Error(`Unknown option: ${flag}`);
  }
  return { options, outputPath };
}

const { options, outputPath } = parseArguments(process.argv.slice(2));
const fixture = `${JSON.stringify(generateDeterministicDemoEvidenceSet(options), null, 2)}\n`;
if (outputPath) {
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, fixture, { encoding: "utf8", flag: "wx" });
  console.log(`Wrote deterministic synthetic evidence fixtures to ${outputPath}`);
} else {
  process.stdout.write(fixture);
}
