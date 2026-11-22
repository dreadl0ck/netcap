import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { frontend, roots, parentOwned, namespaceFor } from './config.mjs';
import { inventory, stableKey, escapeICU } from './inventory.mjs';
const stagePath = path.join(frontend, 'localization/full-staging.json'), stage = JSON.parse(fs.readFileSync(stagePath, 'utf8')), report = [];
const parents = node => { const result = []; for (let p = node.parent; p; p = p.parent) result.push(p); return result; };
for (const file of inventory().files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json') || /\/(?:Preferences|PresentationControls|AppearanceControls)/.test(file.file)) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8'), sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const edits = [], imports = new Set(), covered = [];
  const add = (node, replacement, reason) => { if (covered.some(([a, b]) => node.getStart() >= a && node.end <= b)) return; covered.push([node.getStart(), node.end]); edits.push({ start: node.getStart(sf), end: node.end, replacement, reason }); };
  function hasString(node) { return ts.isStringLiteralLike(node) || ts.isTemplateExpression(node) || ts.isParenthesizedExpression(node) && hasString(node.expression) || ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken && (hasString(node.left) || hasString(node.right)); }
  function build(node) {
    const values = []; let raw = '', pattern = '';
    function append(value) {
      if (ts.isStringLiteralLike(value)) { raw += value.text; pattern += escapeICU(value.text); return; }
      if (ts.isTemplateExpression(value)) { raw += value.head.text; pattern += escapeICU(value.head.text); for (const span of value.templateSpans) { argument(span.expression); raw += span.literal.text; pattern += escapeICU(span.literal.text); } return; }
      if (ts.isBinaryExpression(value) && value.operatorToken.kind === ts.SyntaxKind.PlusToken && hasString(value)) {
        // Numeric addition before the first string remains one numeric expression.
        if (hasString(value.left)) append(value.left); else argument(value.left);
        if (hasString(value.right)) append(value.right); else argument(value.right);
        return;
      }
      argument(value);
    }
    function argument(value) { const name = `arg${values.length}`; values.push({ name, value }); raw += `{${name}}`; pattern += `{${name}}`; }
    append(node);
    if (!/[A-Za-z]{3}/.test(raw.replace(/\{arg\d+\}/g, ''))) return null;
    return { raw, pattern, values };
  }
  function argument(value) {
    const source = value.getText(sf);
    if (ts.isPropertyAccessExpression(value) && value.name.text === 'message' && /^(?:e|err|error|[A-Za-z]+Error)$/.test(value.expression.getText(sf))) { imports.add('errorText'); return `errorText(${value.expression.getText(sf)})`; }
    if (ts.isConditionalExpression(value) && ts.isBinaryExpression(value.condition) && value.condition.operatorToken.kind === ts.SyntaxKind.InstanceOfKeyword && value.condition.right.getText(sf) === 'Error') { imports.add('errorText'); return `errorText(${value.condition.left.getText(sf)})`; }
    return source;
  }
  function visit(node) {
    if (covered.some(([a, b]) => node.getStart() >= a && node.end <= b)) return;
    if (ts.isPropertyAssignment(node) && /^(?:message|msg)$/.test(node.name.getText(sf)) && ts.isBinaryExpression(node.initializer) && hasString(node.initializer)) {
      const sink = parents(node).find(parent => ts.isCallExpression(parent) && /^(?:set(?:Notification|Snackbar|Toast)|notify|showSnackbar)$/.test(parent.expression.getText(sf)));
      if (sink) {
        const part = build(node.initializer);
        if (part) {
          const namespace = namespaceFor(file.file, part.raw), key = stableKey(part.pattern), id = `${namespace}:${key}`;
          stage.messages[id] ??= { namespace, key, message: part.pattern, context: 'Deferred callback/status message. Parameters are evidence or structured errors, not text to translate.', locations: [{ repo: file.repo, file: file.file, line: sf.getLineAndCharacterOfPosition(node.getStart()).line + 1, source: part.raw }] };
          imports.add('message'); add(node.initializer, `message(${JSON.stringify(id)}, { ${part.values.map(value => `${value.name}: ${argument(value.value)}`).join(', ')} })`, 'interpolated-concatenation-with-preserved-numeric-addition'); return;
        }
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  if (!edits.length) continue;
  const declarations = sf.statements.filter(ts.isImportDeclaration), bound = new Set(declarations.flatMap(statement => statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings) ? statement.importClause.namedBindings.elements.map(item => item.name.text) : []));
  const names = [...imports].filter(name => !bound.has(name));
  if (names.length) {
    let module = path.posix.relative(path.posix.dirname(file.file), file.repo === 'netcap-pro' ? 'frontend/src/lib/i18n' : 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n'); if (!module.startsWith('.')) module = './' + module;
    const position = declarations.at(-1)?.end ?? sf.statements[0]?.getStart(sf) ?? 0;
    edits.push({ start: position, end: position, replacement: `\nimport { ${names.join(', ')} } from ${JSON.stringify(module)};\n`, reason: 'deferred-message-imports' });
  }
  let output = text, boundary = text.length;
  for (const edit of edits.sort((a, b) => b.start - a.start)) { if (edit.end > boundary) throw new Error(`Overlapping message migration: ${file.file}`); output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end); boundary = edit.start; }
  fs.writeFileSync(absolute, output); report.push({ file: file.file, edits: edits.map(({ start, reason }) => ({ line: sf.getLineAndCharacterOfPosition(start).line + 1, reason })) });
}
fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
fs.writeFileSync(path.join(frontend, 'localization/concatenated-message-migration.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ files: report.length, messages: Object.keys(stage.messages).length }));
