import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { roots, parentOwned } from './config.mjs';
import { inventory } from './inventory.mjs';
let changes = 0;
for (const file of inventory().files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json')) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8');
  const sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const edits = [], names = new Set();
  function visit(node) {
    if (file.file.endsWith('/pages/BehaviorPage.tsx') && ts.isPropertyAccessExpression(node)) {
      const expression = node.getText(sf);
      if (expression === 'decision.action' && ts.isJsxExpression(node.parent)) { names.add('behaviorActionLabel'); edits.push({ start: node.getStart(sf), end: node.end, text: 'behaviorActionLabel(decision.action)' }); return; }
      if ((expression === 'data.mode' && ts.isJsxExpression(node.parent) && ts.isJsxAttribute(node.parent.parent) && node.parent.parent.name.getText(sf) === 'label') || expression === 'live.state' && ts.isPropertyAssignment(node.parent)) { names.add('enumLabel'); edits.push({ start: node.getStart(sf), end: node.end, text: `enumLabel(${expression})` }); return; }
    }
    if (ts.isCallExpression(node)) {
      if (file.file === 'frontend/src/pages/investigation.tsx' && /^(?:translate|i18nText)$/.test(node.expression.getText(sf)) && node.arguments[0] && /^(?:kind|artifact\.kind)$/.test(node.arguments[0].getText(sf))) { names.add('artifactKindLabel'); edits.push({ start: node.expression.getStart(sf), end: node.expression.end, text: 'artifactKindLabel' }); }
      if (file.file === 'frontend/src/pages/investigation.tsx' && node.expression.getText(sf) === 'run') {
        const notice = node.arguments[1];
        if (notice && ts.isCallExpression(notice) && /^(?:translate|i18nText|finalCopyText)$/.test(notice.expression.getText(sf))) edits.push({ start: notice.expression.getStart(sf), end: notice.expression.end, text: 'i18nMessage' });
      }
      if (/^(?:finalCopyText|translate|i18nText)$/.test(node.expression.getText(sf)) && node.arguments.length === 1) {
        let inner = node.arguments[0];
        while (ts.isCallExpression(inner) && inner.arguments.length === 1 && inner.expression.getText(sf) === node.expression.getText(sf)) inner = inner.arguments[0];
        if (inner !== node.arguments[0]) { edits.push({ start: node.arguments[0].getStart(sf), end: node.arguments[0].end, text: inner.getText(sf) }); return; }
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  if (!edits.length) continue;
  const declarations = sf.statements.filter(ts.isImportDeclaration), bound = new Set(declarations.flatMap(statement => statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings) ? statement.importClause.namedBindings.elements.map(item => item.name.text) : []));
  const needed = [...names].filter(name => !bound.has(name));
  if (needed.length) { const position = declarations.at(-1)?.end ?? 0; edits.push({ start: position, end: position, text: `\nimport { ${needed.join(', ')} } from '../lib/i18n';\n` }); }
  let output = text, boundary = text.length;
  for (const edit of edits.sort((a, b) => b.start - a.start)) { if (edit.end > boundary) throw new Error(`Overlapping deferred binding: ${file.file}`); output = output.slice(0, edit.start) + edit.text + output.slice(edit.end); boundary = edit.start; }
  fs.writeFileSync(absolute, output); changes += edits.length;
}
console.log(JSON.stringify({ correctedDeferredOrRepeatedBindings: changes }));
