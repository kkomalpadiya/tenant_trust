import { spawnSync } from 'node:child_process';
import { readFileSync, statfsSync } from 'node:fs';
import { availableParallelism, freemem, totalmem } from 'node:os';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const config = JSON.parse(readFileSync(new URL('../config/toolchain.json', import.meta.url), 'utf8'));
const args = process.argv.slice(2);
const profile = args.find((arg) => arg.startsWith('--profile='))?.slice(10) ?? 'smoke';
if (!config.profiles[profile] || args.some((arg) => arg !== '--smoke' && !arg.startsWith('--profile='))) {
  console.error('Usage: node scripts/check-environment.mjs [--profile=smoke|core|fabric] [--smoke]');
  process.exit(2);
}
const budget = config.profiles[profile];
const gib = 1024 ** 3;
let failures = 0;
function report(status, name, detail) {
  console.log(`${status} ${name}: ${detail}`);
  if (status === 'FAIL') failures++;
}
function run(command, commandArgs, timeout = 15000) {
  const result = spawnSync(command, commandArgs, { cwd: root, timeout, encoding: 'utf8', windowsHide: true });
  return { ok: !result.error && result.status === 0, text: (result.stdout ?? '').trim(), error: result.error?.message ?? (result.stderr ?? '').trim() };
}
function checkCommand(name, command, commandArgs, accept = () => true) {
  const result = run(command, commandArgs);
  const ok = result.ok && accept(result.text);
  report(ok ? 'PASS' : 'FAIL', name, ok ? result.text : result.error || result.text || 'command failed');
  return ok;
}
console.log(`Tenant Trust environment check (${profile}). This checks tools and resource budgets, not application readiness.`);
checkCommand('Git', 'git', ['--version']);
const major = Number(process.versions.node.split('.')[0]);
report(major === 24 ? 'PASS' : 'FAIL', 'Host Node major', process.versions.node);
if (process.versions.node !== config.node) {
  report('WARN', 'Host Node patch', `Project target is ${config.node}. Use the pinned container or update host Node before installing project dependencies.`);
}
if (process.platform === 'win32') {
  checkCommand('npm', 'cmd.exe', ['/d', '/c', 'npm.cmd --version']);
} else {
  checkCommand('npm', 'npm', ['--version']);
}
checkCommand('Compose v2', 'docker', ['compose', 'version', '--short'], (text) => /^v?2\./.test(text));
const server = run('docker', ['info', '--format', '{{json .}}']);
let dockerReady = false;
if (!server.ok) {
  report('FAIL', 'Docker engine', 'Start Docker Desktop with Linux containers, then rerun this check.');
} else {
  try {
    const info = JSON.parse(server.text);
    dockerReady = info.OSType === 'linux';
    report(dockerReady ? 'PASS' : 'FAIL', 'Docker engine', `${info.ServerVersion}, ${info.OSType}`);
    const memory = Number(info.MemTotal) / gib;
    report(memory >= budget.dockerMemoryGiB ? 'PASS' : 'FAIL', 'Docker memory', `${memory.toFixed(1)} GiB available to engine; ${profile} requires at least ${budget.dockerMemoryGiB} GiB (see local setup guide).`);
    report(Number(info.NCPU) >= 4 ? 'PASS' : 'FAIL', 'Docker CPUs', `${info.NCPU}; project budget requires at least 4.`);
  } catch {
    report('FAIL', 'Docker engine', 'Could not parse engine information.');
  }
}
try {
  const disk = statfsSync(root);
  const free = disk.bavail * disk.bsize / gib;
  report(free >= budget.freeDiskGiB ? 'PASS' : 'FAIL', 'Project disk', `${free.toFixed(1)} GiB free; ${profile} budget is ${budget.freeDiskGiB} GiB.`);
} catch {
  report('FAIL', 'Project disk', 'Could not check free disk space.');
}
report('INFO', 'Host resources', `${(totalmem() / gib).toFixed(1)} GiB RAM, ${(freemem() / gib).toFixed(1)} GiB currently free, ${availableParallelism()} available CPUs.`);
if (freemem() < 2 * gib) report('WARN', 'Host memory pressure', 'Close unneeded applications before starting additional services.');
if (profile === 'smoke') report('INFO', 'Scope', 'Passing smoke does not mean the machine has enough allocated memory for the core or Fabric profiles.');
if (args.includes('--smoke')) {
  if (!dockerReady || failures > 0) {
    report('FAIL', 'Container smoke test', 'Skipped because a prerequisite check failed.');
  } else {
    const code = `const assert=require('node:assert/strict');const c=require('node:crypto');assert.equal(process.versions.node,'${config.node}');assert.equal(process.platform,'linux');const k=c.generateKeyPairSync('ed25519');const m=Buffer.from('tenant-trust-runtime-check');assert(c.verify(null,m,k.publicKey,c.sign(null,m,k.privateKey)));console.log('Node '+process.versions.node+' Linux and Ed25519 sign/verify passed');`;
    // Images are pulled explicitly by the developer so this bounded check never starts an unexpected download.
    const result = run('docker', ['run', '--rm', '--pull=never', '--network=none', '--memory=128m', '--cpus=0.5', config.nodeImage, 'node', '-e', code], 45000);
    report(result.ok ? 'PASS' : 'FAIL', 'Container smoke test', result.ok ? result.text : `Pull ${config.nodeImage} first if missing. ${result.error}`);
  }
}
console.log(failures ? `${failures} check(s) failed.` : 'Required checks for the selected profile passed.');
process.exitCode = failures ? 1 : 0;
