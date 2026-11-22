import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { frontend, roots, parentOwned } from './config.mjs';
import { inventory } from './inventory.mjs';
const report = [];
for (const file of inventory().files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json')) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8'), sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const edits = [];
  function visit(node) {
    if (ts.isCallExpression(node) && /^(?:formatNumber|i18nNumber)$/.test(node.expression.getText(sf))) {
      let program = false;
      for (let p = node.parent; p; p = p.parent) {
        if (ts.isJsxAttribute(p) && /^(?:sx|style|key|id|fontSize|width|height|viewBox|strokeWidth|x|y|cx|cy|r|transform)$/.test(p.name.getText(sf))) program = true;
        if (ts.isJsxAttribute(p) && p.name.getText(sf) === 'value' && /^(?:TextField|Select|MenuItem|Input|OutlinedInput|Slider|Checkbox|Radio|Switch|option|input|select)$/.test(p.parent.parent.tagName?.getText(sf) ?? '')) program = true;
        if (ts.isCallExpression(p) && /^(?:JSON\.stringify|rawCode|parseFloat|parseInt|Number|encodeURIComponent|fetch|api\.)/.test(p.expression.getText(sf))) program = true;
        if (ts.isPropertyAssignment(p) && /^(?:style|sx|vertexShader|fragmentShader|transform|opacity|left|right|top|bottom|width|height)$/.test(p.name.getText(sf))) program = true;
      }
      if (program && node.arguments[0]) {
        const options = node.arguments[1];
        const minimum = options && ts.isObjectLiteralExpression(options) ? options.properties.find(property => ts.isPropertyAssignment(property) && property.name.getText(sf) === 'minimumFractionDigits') : undefined;
        edits.push({ start: node.getStart(sf), end: node.end, replacement: minimum ? `(${node.arguments[0].getText(sf)}).toFixed(${minimum.initializer.getText(sf)})` : `String(${node.arguments[0].getText(sf)})`, reason: 'locale-independent-css-wire-code-or-numeric-rounding' }); return;
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  if (!edits.length) continue;
  let output = text;
  for (const edit of edits.sort((a, b) => b.start - a.start)) output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end);
  fs.writeFileSync(absolute, output); report.push({ file: file.file, edits: edits.map(({ start, reason }) => ({ line: sf.getLineAndCharacterOfPosition(start).line + 1, reason })) });
}
fs.writeFileSync(path.join(frontend, 'localization/program-format-invariants.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ files: report.length, restoredCanonicalFormats: report.reduce((sum, file) => sum + file.edits.length, 0) }));
