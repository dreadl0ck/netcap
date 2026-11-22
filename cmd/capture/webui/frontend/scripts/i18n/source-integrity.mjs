import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { frontend, roots, parentOwned } from './config.mjs';
import { inventory } from './inventory.mjs';
const stage = JSON.parse(fs.readFileSync(path.join(frontend, 'localization/full-staging.json'), 'utf8'));
const snapshot = inventory(), changed = [];
const ancestors = node => { const result = []; for (let p = node.parent; p; p = p.parent) result.push(p); return result; };
for (const file of snapshot.files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json')) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8');
  const sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const edits = [], imports = new Set(), existing = sf.statements.filter(ts.isImportDeclaration);
  const already = new Set(existing.flatMap(statement => statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings) ? statement.importClause.namedBindings.elements.map(item => item.name.text) : []));
  const add = (node, replacement, reason) => edits.push({ start: node.getStart(sf), end: node.end, replacement, reason });
  function visit(node) {
    if (ts.isVariableDeclaration(node) && node.name.getText(sf) === 'formatTimestamp' && node.initializer && /\/(?:Alerts|Analyze)Page\.tsx$/.test(file.file)) {
      add(node.initializer, `(timestamp: number, unit: 'seconds' | 'milliseconds' | 'nanoseconds') => displayTimestamp(timestamp, unit)`, 'delegate-explicit-unit-formatting');
      imports.add('API:formatTimestamp as displayTimestamp'); return;
    }
    if (ts.isCallExpression(node) && /^(?:translate|i18nText|richText|i18nRichText)$/.test(node.expression.getText(sf)) && node.arguments[0] && ts.isStringLiteral(node.arguments[0])) {
      const entry = stage.messages[node.arguments[0].text];
      const program = ancestors(node).some(parent => ts.isCallExpression(parent) && /^(?:JSON\.stringify|console\.|logger\.)/.test(parent.expression.getText(sf)));
      if (entry && program) {
        if (node.arguments.length === 1) {
          const raw = entry.locations[0]?.source ?? entry.message;
          add(node, JSON.stringify(raw), 'preserve-json-or-log-supplier-capture-data'); return;
        }
        imports.add('messageSource'); imports.add('message');
        add(node, `messageSource(message(${node.arguments.map(argument => argument.getText(sf)).join(', ')}))`, 'preserve-english-structured-diagnostic-program'); return;
      }
    }
    if (ts.isIdentifier(node) && /^(?:logContent|errorLogContent)$/.test(node.text) && ts.isBinaryExpression(node.parent) && node.parent.left === node && node.parent.operatorToken.kind === ts.SyntaxKind.BarBarToken && ancestors(node).some(ts.isJsxExpression)) {
      imports.add('renderText'); add(node, `renderText(${node.text})`, 'raw-log-or-deferred-error-display-without-source-translation'); return;
    }
    if (ts.isPropertyAccessExpression(node) && node.name.text === 'message' && /^(?:result|response|res|data)$/.test(node.expression.getText(sf))) {
      const sink = ancestors(node).find(ts.isCallExpression);
      if (sink && /^(?:set.*(?:Success|Error|Message)|notify|showSnackbar)$/.test(sink.expression.getText(sf))) {
        imports.add('metadataMessage'); add(node, `metadataMessage(${node.expression.getText(sf)}, 'message')`, 'retain-structured-backend-message-for-locale-changes'); return;
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  if (!edits.length) continue;
  const names = [...imports].filter(name => !already.has(name.replace(/^API:/, '').split(' as ').at(-1)));
  let module = file.repo === 'netcap-pro' ? path.posix.relative(path.posix.dirname(file.file), 'frontend/src/lib/i18n') : path.posix.relative(path.posix.dirname(file.file), 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n');
  if (!module.startsWith('.')) module = './' + module;
  const declarations = [];
  if (names.some(name => !name.startsWith('API:'))) declarations.push(`import { ${names.filter(name => !name.startsWith('API:')).join(', ')} } from ${JSON.stringify(module)};`);
  if (names.some(name => name.startsWith('API:'))) declarations.push(`import { ${names.filter(name => name.startsWith('API:')).map(name => name.slice(4)).join(', ')} } from '../lib/api';`);
  const position = existing.at(-1)?.end ?? sf.statements[0]?.getStart(sf) ?? 0;
  if (declarations.length) edits.push({ start: position, end: position, replacement: '\n' + declarations.join('\n') + '\n', reason: 'integrity-imports' });
  let output = text, boundary = text.length;
  for (const edit of edits.sort((a, b) => b.start - a.start)) { if (edit.end > boundary) throw new Error(`Overlapping integrity edits: ${file.file}`); output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end); boundary = edit.start; }
  fs.writeFileSync(absolute, output); changed.push({ file: file.file, edits: edits.map(({ start, reason }) => ({ line: sf.getLineAndCharacterOfPosition(start).line + 1, reason })) });
}
fs.writeFileSync(path.join(frontend, 'localization/source-integrity.json'), JSON.stringify(changed, null, 2) + '\n');
console.log(JSON.stringify({ files: changed.length }));
