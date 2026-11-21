import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const directory = dirname(fileURLToPath(import.meta.url));
const root = resolve(directory, '../..');
const cli = process.env.ARCHIFY_CLI || join(homedir(), '.agents/skills/archify/bin/archify.mjs');
const verificationPath = join(directory, 'verification.json');
const hash = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const specs = readdirSync(join(directory, 'specs')).filter(name => name.endsWith('.json')).sort();
const gates = ['validate', 'deliver', 'check', 'browser-check'];
const args = process.argv.slice(2);
const selected = args.length && !args.includes('--check') ? args.map(name => `${name}.json`) : specs;

if ((args.includes('--check') && args.length !== 1) || selected.some(name => !specs.includes(name))) {
  throw new Error('Usage: node docs/diagrams/render.mjs [--check | diagram-name ...]');
}

function checkVerification(verification) {
  if (verification.diagrams.length !== specs.length) throw new Error('Diagram inventory changed; render again');
  for (const name of specs) {
    const specification = `docs/diagrams/specs/${name}`;
    const spec = JSON.parse(readFileSync(join(root, specification), 'utf8'));
    const entry = verification.diagrams.find(item => item.specification === specification);
    if (!entry || entry.artifact !== spec.meta.output || entry.revision !== spec.meta.repository.revision ||
        entry.specificationSHA256 !== hash(join(root, specification)) ||
        entry.artifactSHA256 !== hash(join(root, entry.artifact)) ||
        gates.some(gate => entry.gates[gate] !== 'pass')) {
      throw new Error(`${name}: stale or incomplete verification; render again`);
    }
  }
}

if (args.includes('--check')) {
  checkVerification(JSON.parse(readFileSync(verificationPath, 'utf8')));
  console.log(`Verified ${specs.length} specifications and HTML artifacts against their passing receipts.`);
} else {
  if (!existsSync(cli)) throw new Error('Install Archify globally or set ARCHIFY_CLI to bin/archify.mjs');
  const run = join(directory, '.validation', randomUUID());
  mkdirSync(run, { recursive: true });
  const previous = existsSync(verificationPath) ? JSON.parse(readFileSync(verificationPath, 'utf8')).diagrams : [];
  const updated = new Map(previous.map(entry => [entry.specification, entry]));
  for (const name of selected) {
    const specification = `docs/diagrams/specs/${name}`;
    const spec = JSON.parse(readFileSync(join(root, specification), 'utf8'));
    writeFileSync(join(run, name), readFileSync(join(root, specification)));
    const result = spawnSync(process.execPath, [cli, 'finalize', spec.diagram_type,
      specification, spec.meta.output, '--repo-root', root, '--quality', spec.meta.quality_profile,
      '--out-dir', join(run, name.slice(0, -5)), '--json'], { cwd: root, encoding: 'utf8' });
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.error) throw result.error;
    if (result.status !== 0) process.exit(result.status || 1);
    const receipt = JSON.parse(result.stdout);
    if (!receipt.ok || gates.some(gate => receipt.gates[gate] !== 'pass')) {
      throw new Error(`${name}: finalize did not pass all gates`);
    }
    updated.set(specification, { specification, artifact: spec.meta.output, type: spec.diagram_type,
      revision: spec.meta.repository.revision, specificationSHA256: receipt.specification.sha256,
      artifactSHA256: receipt.artifact.sha256, archifyVersion: receipt.update.installedVersion,
      gates: receipt.gates, visualReview: receipt.visualReview });
  }
  const diagrams = specs.map(name => updated.get(`docs/diagrams/specs/${name}`));
  const verification = { version: 1, diagrams };
  if (diagrams.some(entry => !entry)) throw new Error('Render all diagrams before publishing verification');
  checkVerification(verification);
  writeFileSync(verificationPath, `${JSON.stringify(verification, null, 2)}\n`);
  console.log(`Saved portable verification for ${diagrams.length} diagrams to ${relative(root, verificationPath)}.`);
}
