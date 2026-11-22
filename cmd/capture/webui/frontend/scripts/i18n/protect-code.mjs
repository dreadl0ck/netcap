import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { frontend, roots, parentOwned } from './config.mjs';
import { inventory, escapeICU } from './inventory.mjs';
const require = process.env.NETCAP_I18N_DEPS_ROOT ? createRequire(path.join(process.env.NETCAP_I18N_DEPS_ROOT, 'package.json')) : createRequire(import.meta.url);
const { parse } = require('@formatjs/icu-messageformat-parser');
const stagePath = path.join(frontend, 'localization/full-staging.json'), stage = JSON.parse(fs.readFileSync(stagePath, 'utf8'));
const snapshot = inventory(), mappings = new Map(), files = new Map();
const codeTag = node => ts.isJsxElement(node) && ['code', 'kbd', 'samp', 'pre'].includes(node.openingElement.tagName.getText());
const parents = node => { const result = []; for (let p = node.parent; p; p = p.parent) result.push(p); return result; };
for (const file of snapshot.files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json')) continue;
  const absolute = path.join(roots[file.repo], file.file), source = fs.readFileSync(absolute, 'utf8');
  const sf = ts.createSourceFile(file.file, source, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const calls = [];
  function visit(node) {
    if (ts.isCallExpression(node) && /^(?:translate|i18nText|richText|i18nRichText)$/.test(node.expression.getText(sf)) && node.arguments[0] && ts.isStringLiteral(node.arguments[0]) && stage.messages[node.arguments[0].text]) {
      const id = node.arguments[0].text;
      if (parents(node).some(codeTag)) calls.push({ node, id, raw: true });
      else if (node.arguments[1] && ts.isObjectLiteralExpression(node.arguments[1])) {
        const tags = node.arguments[1].properties.filter(ts.isPropertyAssignment).filter(property => {
          const value = property.initializer;
          return (ts.isArrowFunction(value) || ts.isFunctionExpression(value)) && codeTag(value.body);
        }).map(property => property.name.getText(sf));
        if (tags.length) { mappings.set(id, new Set([...(mappings.get(id) ?? []), ...tags])); calls.push({ node, id, raw: false }); }
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf); if (calls.length) files.set(absolute, { sf, source, file, calls });
}
const protectedPatterns = new Map();
for (const [id, names] of mappings) {
  const entry = stage.messages[id], ast = parse(entry.message, { captureLocation: true });
  const edits = [], slots = new Map();
  function serialize(elements, count) {
    return elements.map(element => element.type === 0 ? escapeICU(element.value) : element.type === 7 && count ? `{${count}}` : element.type === 8 ? `<${element.value}>${serialize(element.children, count)}</${element.value}>` : element.type === 1 || element.type === 2 ? `{${element.value}}` : entry.message.slice(element.location.start.offset, element.location.end.offset)).join('');
  }
  function walk(elements, count) {
    for (const element of elements) {
      if (element.type === 8 && names.has(element.value)) {
        const slot = `code${slots.size}`;
        const pattern = serialize(element.children, count);
        slots.set(slot, pattern);
        edits.push({ start: element.location.start.offset, end: element.location.end.offset, replacement: `<${element.value}>{${slot}}</${element.value}>` });
      } else {
        if (element.children) walk(element.children, count);
        if (element.options) Object.values(element.options).forEach(option => walk(option.value, element.type === 6 ? element.value : count));
      }
    }
  }
  walk(ast);
  let message = entry.message;
  for (const edit of edits.sort((a, b) => b.start - a.start)) message = message.slice(0, edit.start) + edit.replacement + message.slice(edit.end);
  protectedPatterns.set(id, slots); entry.message = message;
}
for (const [absolute, { sf, source, file, calls }] of files) {
  const edits = [], covered = [];
  for (const { node, id, raw } of calls.sort((a, b) => a.node.getStart() - b.node.getStart())) {
    if (covered.some(([a, b]) => node.getStart() >= a && node.end <= b)) continue;
    if (raw) {
      const entry = stage.messages[id];
      edits.push({ start: node.getStart(sf), end: node.end, replacement: `rawCode(${JSON.stringify(entry.message)}${node.arguments[1] ? ', ' + node.arguments[1].getText(sf) : ''})` });
      covered.push([node.getStart(), node.end]);
    } else {
      const object = node.arguments[1];
      const slots = protectedPatterns.get(id);
      if (slots?.size) {
        const bindings = [...slots].map(([name, pattern]) => `${name}: rawCode(${JSON.stringify(pattern)}, __codeValues)`).join(', ');
        edits.push({ start: node.getStart(sf), end: node.end, replacement: `((__codeValues: Record<string, unknown>) => ${node.expression.getText(sf)}(${JSON.stringify(id)}, { ...__codeValues, ${bindings} }))(${object.getText(sf)})` });
        covered.push([node.getStart(), node.end]);
      }
    }
  }
  if (!edits.length) continue;
  const imports = sf.statements.filter(ts.isImportDeclaration), position = imports.at(-1)?.end ?? sf.statements[0]?.getStart(sf) ?? 0;
  let module = path.posix.relative(path.posix.dirname(file.file), file.repo === 'netcap-pro' ? 'frontend/src/lib/i18n' : 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n');
  if (!module.startsWith('.')) module = './' + module;
  edits.push({ start: position, end: position, replacement: `\nimport { rawCode } from ${JSON.stringify(module)};\n` });
  let output = source, boundary = source.length;
  for (const edit of edits.sort((a, b) => b.start - a.start)) { if (edit.end > boundary) throw new Error(`Overlapping code protection: ${file.file}`); output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end); boundary = edit.start; }
  fs.writeFileSync(absolute, output);
}
fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
fs.writeFileSync(path.join(frontend, 'localization/code-protection.json'), JSON.stringify([...protectedPatterns].map(([id, slots]) => ({ id, codeSlots: Object.fromEntries(slots) })), null, 2) + '\n');
console.log(JSON.stringify({ files: files.size, opaqueCodeMessages: protectedPatterns.size }));
