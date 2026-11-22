import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { frontend, roots, namespaceFor, parentOwned } from './config.mjs';
import { inventory } from './inventory.mjs';

const directory = path.join(frontend, 'localization'), file = path.join(directory, 'full-staging.json');
const stage = JSON.parse(fs.readFileSync(file, 'utf8')), changes = new Map();
for (const [id, entry] of Object.entries(stage.messages)) {
  if (entry.namespace !== 'ui') continue;
  const namespace = namespaceFor(entry.locations[0].file, entry.message);
  if (namespace === 'ui') continue;
  const next = `${namespace}:${entry.key}`;
  stage.messages[next] ??= { ...entry, namespace };
  changes.set(id, next); delete stage.messages[id];
}
for (const source of inventory().files) {
  if (parentOwned(source.file) || source.html || source.file.endsWith('.json')) continue;
  const absolute = path.join(roots[source.repo], source.file), text = fs.readFileSync(absolute, 'utf8');
  const sf = ts.createSourceFile(source.file, text, ts.ScriptTarget.Latest, true, source.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS), edits = [];
  const visit = node => { if (ts.isStringLiteralLike(node) && changes.has(node.text)) edits.push({ start: node.getStart(sf), end: node.end, text: JSON.stringify(changes.get(node.text)) }); ts.forEachChild(node, visit); };
  visit(sf);
  if (!edits.length) continue;
  let output = text;
  for (const edit of edits.sort((a, b) => b.start - a.start)) output = output.slice(0, edit.start) + edit.text + output.slice(edit.end);
  fs.writeFileSync(absolute, output);
}
const parentFile = path.join(directory, 'parent-messages.json'), parent = JSON.parse(fs.readFileSync(parentFile, 'utf8'));
for (const item of parent) if (changes.has(item.key)) item.key = changes.get(item.key);
fs.writeFileSync(parentFile, JSON.stringify(parent, null, 2) + '\n');
const aliasesFile = path.join(frontend, 'packages/netcap-ui/src/lib/i18n/backend-ids.json'), aliases = JSON.parse(fs.readFileSync(aliasesFile, 'utf8'));
for (const [id, target] of Object.entries(aliases)) if (changes.has(target)) aliases[id] = changes.get(target);
fs.writeFileSync(aliasesFile, JSON.stringify(aliases, null, 2) + '\n');
const reportFile = path.join(directory, 'edition-classification.json'), previous = fs.existsSync(reportFile) ? JSON.parse(fs.readFileSync(reportFile, 'utf8')) : {};
fs.writeFileSync(reportFile, JSON.stringify({ ...previous, ...Object.fromEntries(changes) }, null, 2) + '\n');
fs.writeFileSync(file, JSON.stringify(stage, null, 2) + '\n');
console.log(JSON.stringify({ catalogNamespacesCorrected: changes.size, parentFilesEdited: 0 }));
