import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { frontend, roots, parentOwned, namespaceFor } from './config.mjs';
import { inventory, stableKey, escapeICU } from './inventory.mjs';
const stagePath = path.join(frontend, 'localization/full-staging.json'), stage = JSON.parse(fs.readFileSync(stagePath, 'utf8')), report = [];
const fallback = new Set(['Unknown error', 'Unknown', 'Unavailable', 'Not available', 'Not set', 'Not observed', 'not available', 'status unavailable']);
for (const file of inventory().files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json')) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8'), sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const edits = [], used = new Set(), ranges = [], helperParameters = new Map();
  const ancestors = node => { const result = []; for (let p = node.parent; p; p = p.parent) result.push(p); return result; };
  const add = (node, replacement, reason) => { if (ranges.some(([a, b]) => node.getStart() >= a && node.end <= b)) return; ranges.push([node.getStart(), node.end]); edits.push({ start: node.getStart(sf), end: node.end, replacement, reason }); };
  function sourceMessage(node, value, deferred) {
    const namespace = namespaceFor(file.file, value), message = escapeICU(value), key = stableKey(message), id = `${namespace}:${key}`;
    stage.messages[id] ??= { namespace, key, message, context: '', locations: [{ repo: file.repo, file: file.file, line: sf.getLineAndCharacterOfPosition(node.getStart()).line + 1, source: value }] };
    used.add(deferred ? 'message as i18nParameterMessage' : 'translate as i18nParameterText');
    return `${deferred ? 'i18nParameterMessage' : 'i18nParameterText'}(${JSON.stringify(id)})`;
  }
  function definitions(node) {
    if ((ts.isFunctionDeclaration(node) || ts.isArrowFunction(node)) && node.body) {
      const name = node.name?.text ?? (ts.isVariableDeclaration(node.parent) ? node.parent.name.getText(sf) : '');
      const indices = [];
      node.parameters.forEach((parameter, index) => {
        const label = parameter.name.getText(sf);
        if (!/^(?:label|title|description|caption|helperText|tooltip|learnHint)$/.test(label)) return;
        let display = false, identity = false;
        function visit(child) {
          if (ts.isIdentifier(child) && child.text === label && child !== parameter.name) for (let p = child.parent; p; p = p.parent) {
            if (ts.isJsxExpression(p)) {
              if (ts.isJsxAttribute(p.parent)) { const attr = p.parent.name.getText(sf); if (/^(?:key|id|value|name|href|path)$/.test(attr)) identity = true; if (/^(?:label|title|placeholder|helperText|aria-label|data-learn)$/.test(attr)) display = true; }
              else display = true;
              break;
            }
            if (ts.isStatement(p)) break;
          }
          ts.forEachChild(child, visit);
        }
        visit(node.body); if (display && !identity) indices.push(index);
      });
      if (indices.length) helperParameters.set(name, indices);
    }
    ts.forEachChild(node, definitions);
  }
  definitions(sf);
  function visit(node) {
    if (ranges.some(([a, b]) => node.getStart() >= a && node.end <= b)) return;
    if (ts.isCallExpression(node)) {
      for (const index of helperParameters.get(node.expression.getText(sf)) ?? []) {
        const argument = node.arguments[index];
        if (argument && ts.isStringLiteralLike(argument) && /[A-Za-z]/.test(argument.text)) add(argument, sourceMessage(argument, argument.text, false), 'literal-display-helper-argument-with-stable-identity');
      }
      if (/^(?:translate|i18nText)$/.test(node.expression.getText(sf))) {
        const outer = ancestors(node).find(parent => ts.isCallExpression(parent) && /^(?:message|i18nMessage)$/.test(parent.expression.getText(sf)) && parent.arguments[1] && node.getStart() > parent.arguments[1].getStart() && node.end <= parent.arguments[1].end);
        if (outer) { used.add('message as i18nParameterMessage'); add(node.expression, 'i18nParameterMessage', 'defer-nested-message-parameters-until-render'); }
      }
    }
    if (ts.isStringLiteralLike(node) && fallback.has(node.text)) {
      const owner = ancestors(node).find(parent => ts.isCallExpression(parent) && /^(?:message|i18nMessage)$/.test(parent.expression.getText(sf)));
      const property = ancestors(node).find(ts.isPropertyAssignment);
      if (owner?.arguments[1] && node.getStart() >= owner.arguments[1].getStart() && property && /^arg\d+$/.test(property.name.getText(sf))) add(node, sourceMessage(node, node.text, true), 'app-authored-fallback-parameter-not-captured-data');
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  if (!edits.length) continue;
  const imports = sf.statements.filter(ts.isImportDeclaration), bound = new Set(imports.flatMap(statement => statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings) ? statement.importClause.namedBindings.elements.map(item => item.name.text) : []));
  const names = [...used].filter(name => !bound.has(name.split(' as ').at(-1)));
  if (names.length) {
    let module = path.posix.relative(path.posix.dirname(file.file), file.repo === 'netcap-pro' ? 'frontend/src/lib/i18n' : 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n'); if (!module.startsWith('.')) module = './' + module;
    const position = imports.at(-1)?.end ?? sf.statements[0]?.getStart(sf) ?? 0;
    edits.push({ start: position, end: position, replacement: `\nimport { ${names.join(', ')} } from ${JSON.stringify(module)};\n`, reason: 'parameter-localization-imports' });
  }
  let output = text, boundary = text.length;
  for (const edit of edits.sort((a, b) => b.start - a.start)) { if (edit.end > boundary) throw new Error(`Overlapping parameter text: ${file.file}`); output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end); boundary = edit.start; }
  fs.writeFileSync(absolute, output); report.push({ file: file.file, edits: edits.map(({ start, reason }) => ({ line: sf.getLineAndCharacterOfPosition(start).line + 1, reason })) });
}
fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
fs.writeFileSync(path.join(frontend, 'localization/parameter-text-migration.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ files: report.length, messages: Object.keys(stage.messages).length }));
