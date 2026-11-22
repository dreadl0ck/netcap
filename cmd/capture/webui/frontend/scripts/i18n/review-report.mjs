import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { frontend, parentOwned, sourceFilePath } from './config.mjs';
import { inventory } from './inventory.mjs';
const metadataIndex = process.argv.indexOf('--metadata');
if (metadataIndex !== -1) {
  const repo = process.argv[metadataIndex + 1], file = process.argv[metadataIndex + 2];
  const source = fs.readFileSync(sourceFilePath(repo, file), 'utf8');
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const results = [];
  function visit(node) {
    if (ts.isJsxElement(node) && node.openingElement.tagName.getText(sf) === 'Button' && node.openingElement.attributes.getText(sf).includes('setDetail')) results.push(node.getText(sf));
    const display = ts.isJsxExpression(node) && !ts.isJsxAttribute(node.parent) || ts.isJsxAttribute(node) && /^(?:label|title|primary|secondary|helperText|placeholder|aria-label|data-learn)$/.test(node.name.getText(sf));
    const text = display ? node.getText(sf) : '';
    if (display && text.length < 1500 && /\b(?:state|status|label|name|description|quality|explanation|context|category|message|error|stepProgress|failures)\b/.test(text)) results.push(text);
    ts.forEachChild(node, visit);
  }
  visit(sf); console.log(results.join('\n')); process.exit(0);
}
const snapshot = inventory();
if (process.argv.includes('--presentation')) {
  const decisions = JSON.parse(fs.readFileSync(path.join(frontend, 'localization/decisions.json'), 'utf8'));
  const pending = snapshot.files.filter(file => !parentOwned(file.file)).flatMap(file => ['formatting', 'dynamicUI', 'dynamicTranslations'].flatMap(kind => (file[kind] ?? []).filter(site => !Object.values(decisions[kind] ?? {}).some(decision => decision.expression === site.expression && decision.reason)).map(site => ({ repo: file.repo, file: file.file, kind, ...site }))));
  fs.writeFileSync(path.join(frontend, 'localization/presentation-review.jsonl'), pending.map(item => JSON.stringify(item)).join('\n') + '\n');
  console.log(JSON.stringify({ pending: pending.length, byKind: Object.fromEntries(['formatting', 'dynamicUI', 'dynamicTranslations'].map(kind => [kind, pending.filter(item => item.kind === kind).length])) }));
  process.exit(0);
}
const groups = [];
for (const file of snapshot.files) {
  if (parentOwned(file.file)) continue;
  const occurrences = file.occurrences.filter(item => ['display', 'review'].includes(item.classification) && /\p{L}/u.test(item.source));
  if (occurrences.length) groups.push({ repo: file.repo, file: file.file, occurrences: occurrences.map(({ id, line, source, classification, reason }) => ({ id, line, source, classification, reason })) });
}
fs.writeFileSync(path.join(frontend, 'localization/review-remaining.json'), JSON.stringify(groups, null, 2) + '\n');
fs.writeFileSync(path.join(frontend, 'localization/review-prose.jsonl'), groups.flatMap(group => group.occurrences.filter(item => /\s/.test(item.source) && !/^(?:rgba?\(|linear-gradient|radial-gradient|var\(|calc\(|@|\/|\.\.|#)/.test(item.source)).map(item => JSON.stringify({ file: group.file, line: item.line, source: item.source, reason: item.reason }))).join('\n') + '\n');
console.log(JSON.stringify({ files: groups.length, occurrences: groups.reduce((sum, group) => sum + group.occurrences.length, 0), dynamicTranslations: snapshot.files.flatMap(file => file.dynamicTranslations.map(site => ({ file: file.file, ...site }))) }, null, 2));
