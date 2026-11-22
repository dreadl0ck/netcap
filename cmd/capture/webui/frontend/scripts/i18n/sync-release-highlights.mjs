import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { frontend, pro, namespaceFor } from './config.mjs';
import { stableKey } from './inventory.mjs';

export function releaseEntries(version) {
  if (!/^\d+\.\d+\.\d+$/.test(version ?? '')) throw new Error('Supply a release version, e.g. --version 1.7.0');
  const files = ['frontend/src/lib/releaseHighlights.appstore.json', 'frontend/src/lib/releaseHighlights.json'];
  const records = files.map(file => {
    const text = fs.readFileSync(path.join(pro, file), 'utf8');
    const entries = JSON.parse(text)[version];
    if (!Array.isArray(entries) || !entries.length) throw new Error(`Missing ${version} highlights: ${file}`);
    return { file, text, sources: entries.flatMap(entry => [entry.title, entry.description]) };
  });
  const store = new Set(records[0].sources), messages = new Map();
  for (const { file, text, sources } of records) for (const source of sources) {
    if (typeof source !== 'string' || !source.trim()) throw new Error(`Invalid release copy: ${file}`);
    const namespace = store.has(source) ? 'ui' : namespaceFor(file, source);
    const id = `${namespace}:${stableKey(source)}`;
    const entry = messages.get(id) ?? { namespace, key: stableKey(source), message: source, context: `${version} release highlight; store applicability follows the explicit App Store release file.`, locations: [] };
    entry.locations.push({ repo: 'netcap-pro', file, line: text.slice(0, text.indexOf(JSON.stringify(source))).split('\n').length, source });
    messages.set(id, entry);
  }
  return Object.fromEntries(messages);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const index = process.argv.indexOf('--version'), version = index === -1 ? undefined : process.argv[index + 1];
  const messages = releaseEntries(version);
  const file = path.join(frontend, 'localization/full-staging.json'), stage = JSON.parse(fs.readFileSync(file, 'utf8'));
  let added = 0;
  for (const [id, entry] of Object.entries(messages)) {
    if (stage.messages[id] && stage.messages[id].message !== entry.message) throw new Error(`Catalog key collision: ${id}`);
    if (!stage.messages[id]) { stage.messages[id] = entry; added++; }
  }
  if (process.argv.includes('--write')) fs.writeFileSync(file, JSON.stringify(stage, null, 2) + '\n');
  console.log(JSON.stringify({ version, write: process.argv.includes('--write'), uniqueMessages: Object.keys(messages).length, added, namespaces: Object.fromEntries(['ui', 'direct', 'removed'].map(namespace => [namespace, Object.values(messages).filter(entry => entry.namespace === namespace).length])) }, null, 2));
}
