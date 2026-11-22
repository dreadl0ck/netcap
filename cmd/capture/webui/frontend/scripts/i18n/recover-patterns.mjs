import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { frontend, roots, parentOwned, namespaceFor } from './config.mjs';
import { inventory, stableKey, escapeICU } from './inventory.mjs';
const stagePath = path.join(frontend, 'localization/full-staging.json');
const stage = JSON.parse(fs.readFileSync(stagePath, 'utf8'));
const snapshot = inventory(), required = new Set();
for (const file of snapshot.files) for (const occurrence of file.occurrences) if (occurrence.messageReference && /^(ui|direct|removed):m_/.test(occurrence.source) && !stage.messages[occurrence.source]) required.add(occurrence.source);
const baseline = JSON.parse(fs.readFileSync('/var/folders/sb/n7njgj0s1ln8wkb4j9hs4n8h0000gn/T/opencode/netcap-i18n-source-baseline.json', 'utf8'));
for (const file of baseline) {
  const sf = ts.createSourceFile(file.file, file.text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  function visit(node) {
    if (ts.isStringLiteralLike(node) || ts.isTemplateExpression(node)) {
      let pattern = ts.isTemplateExpression(node) ? escapeICU(node.head.text) : escapeICU(node.text);
      if (ts.isTemplateExpression(node)) node.templateSpans.forEach((span, index) => { pattern += `{arg${index}}` + escapeICU(span.literal.text); });
      const key = stableKey(pattern);
      for (const namespace of ['ui', 'direct', 'removed']) if (required.has(`${namespace}:${key}`)) {
        stage.messages[`${namespace}:${key}`] = { namespace, key, message: pattern, context: '', locations: [{ repo: file.repo, file: file.file, line: sf.getLineAndCharacterOfPosition(node.getStart()).line + 1, source: pattern }] };
        required.delete(`${namespace}:${key}`);
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
}
const replacements = new Map();
for (const [oldKey, entry] of Object.entries(stage.messages)) {
  if (entry.message.includes(', plural,') || entry.message.includes(', selectordinal,')) continue;
  const message = entry.message.replaceAll("'#'", '#').replaceAll("'>'", '>');
  if (message === entry.message) continue;
  const key = stableKey(message, entry.context ?? ''), qualified = `${entry.namespace}:${key}`;
  stage.messages[qualified] = { ...entry, key, message };
  delete stage.messages[oldKey]; replacements.set(oldKey, qualified);
}
for (const file of snapshot.files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json')) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8');
  let output = text;
  for (const [oldKey, key] of replacements) output = output.replaceAll(JSON.stringify(oldKey), JSON.stringify(key)).replaceAll(`'${oldKey}'`, `'${key}'`);
  if (output !== text) fs.writeFileSync(absolute, output);
}
const parentPath = path.join(frontend, 'localization/parent-messages.json');
const parent = JSON.parse(fs.readFileSync(parentPath, 'utf8'));
parent.forEach(entry => { if (replacements.has(entry.key)) entry.key = replacements.get(entry.key); });
fs.writeFileSync(parentPath, JSON.stringify(parent, null, 2) + '\n');
fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
console.log(JSON.stringify({ unrecoveredReferences: [...required], correctedLiteralQuoting: replacements.size, messages: Object.keys(stage.messages).length }));
if (required.size) process.exitCode = 1;
