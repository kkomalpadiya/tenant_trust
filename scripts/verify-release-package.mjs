import { access, readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const requiredFiles = [
  "docs/architecture/system-overview.md",
  "docs/api-reference.md",
  "docs/demo-script.md",
  "docs/reports/final-project-report.md",
  "docs/reports/effectiveness-and-isolation-evaluation.md",
  "docs/reports/latency-throughput-and-recovery-evaluation.md",
  "docs/reports/ablation-study-and-research-conclusions.md",
  "docs/release-checklist.md",
  "docs/presentation/Tenant_Trust_Final_Demo.pptx",
];

for (const relativePath of requiredFiles) {
  const absolutePath = resolve(root, relativePath);
  await access(absolutePath);
  const metadata = await stat(absolutePath);
  if (!metadata.isFile() || metadata.size === 0) {
    throw new Error(`Release artifact is missing or empty: ${relativePath}`);
  }
}

const read = async (relativePath) => readFile(resolve(root, relativePath), "utf8");
const readme = await read("README.md");
for (const relativePath of requiredFiles.filter((file) => file.endsWith(".md"))) {
  const markdownTarget = relativePath.replace(/^docs\//u, "docs/");
  if (!readme.includes(`(${markdownTarget})`)) {
    throw new Error(`README does not link release document: ${relativePath}`);
  }
}

const apiReference = await read("docs/api-reference.md");
for (const route of [
  "/v1/profile",
  "/v1/tenant-records",
  "/v1/tenant-records/{recordId}",
  "/v1/tenant-records/export",
  "/v1/admin/membership-reviews",
  "/v1/step-up/challenges",
  "/v1/step-up/challenges/{challengeId}/verifications",
  "/v1/evidence",
]) {
  if (!apiReference.includes(route)) throw new Error(`API reference is missing route: ${route}`);
}

const domain = await read("apps/review-demo/demo-domain.mjs");
for (const marker of [
  "completedPhases: 10",
  "totalPhases: 10",
  "completedTasks: 100",
  "totalTasks: 100",
  'currentTask: "T10.10"',
  "nextTask: null",
]) {
  if (!domain.includes(marker)) throw new Error(`Review state is missing completion marker: ${marker}`);
}

const dashboard = await read("apps/review-demo/public/index.html");
for (const marker of ["Phase 10 complete", ">100%<", "width:100%", "All implementation phases complete"]) {
  if (!dashboard.includes(marker)) throw new Error(`Dashboard is missing completion marker: ${marker}`);
}

const releaseText = await Promise.all(requiredFiles
  .filter((file) => file.endsWith(".md"))
  .map(read));
const unresolved = /\[(?:Guide Name|Review Date|TODO|TBD)\]/u;
if (releaseText.some((content) => unresolved.test(content))) {
  throw new Error("Release documentation contains an unresolved placeholder.");
}

console.log("PASS final release package is complete.");
