import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { frontend } from './config.mjs';
import { inventory, stableKey } from './inventory.mjs';

/** Staging data only; unresolved strings never become English fallback entries. */
export function extract(snapshot, decisions = { occurrences: {} }) {
  const messages = {};
  const pending = [];
  for (const file of snapshot.files) for (const occurrence of file.occurrences) {
    if (['canonical', 'localized'].includes(occurrence.classification)) continue;
    const decision = decisions.occurrences?.[occurrence.id];
    if (decision?.source && decision.source !== occurrence.source) throw new Error(`Stale decision: ${occurrence.id}`);
    if (decision?.action === 'keep') {
      if (!decision.reason?.trim()) throw new Error(`Keep needs a reason: ${occurrence.id}`);
      continue;
    }
    const approved = decision?.action === 'translate' || occurrence.migration === 'safe-jsx';
    const message = decision?.message ?? occurrence.message;
    const key = decision?.key ?? stableKey(message, decision?.context ?? '');
    const namespace = decision?.namespace ?? occurrence.namespace;
    if (!approved) pending.push({ repo: file.repo, file: file.file, id: occurrence.id, line: occurrence.line, reason: occurrence.reason, proposedKey: `${namespace}:${key}` });
    if (!approved) continue;
    const qualified = `${namespace}:${key}`;
    if (messages[qualified] && messages[qualified].message !== message) throw new Error(`Catalog collision: ${qualified}`);
    messages[qualified] ??= { namespace, key, message, context: decision?.context ?? '', locations: [] };
    messages[qualified].locations.push({ repo: file.repo, file: file.file, id: occurrence.id, line: occurrence.line, source: occurrence.source });
  }
  return { schemaVersion: 1, status: 'staging-not-runtime', messages, pending };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const decisions = JSON.parse(fs.readFileSync(path.join(frontend, 'localization/decisions.json'), 'utf8'));
  const snapshotIndex = process.argv.indexOf('--inventory');
  const snapshot = snapshotIndex === -1 ? inventory() : JSON.parse(fs.readFileSync(process.argv[snapshotIndex + 1], 'utf8'));
  const result = extract(snapshot, decisions);
  const index = process.argv.indexOf('--out');
  if (index === -1) throw new Error('Supply --out for the staging catalog');
  fs.writeFileSync(process.argv[index + 1], JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({ approvedUniqueMessages: Object.keys(result.messages).length, pendingOccurrences: result.pending.length }));
}
