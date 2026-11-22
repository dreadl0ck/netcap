import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { frontend, roots, parentOwned } from './config.mjs';
import { inventory } from './inventory.mjs';

const directory = path.join(frontend, 'localization');
const stageFile = path.join(directory, 'full-staging.json');
const stage = JSON.parse(fs.readFileSync(stageFile, 'utf8'));
const findings = [], restored = new Set();
const comparisons = new Set([ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken]);
function canonicalContext(node, sf) {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (ts.isFunctionLike(parent) || ts.isStatement(parent)) break;
    if (ts.isBinaryExpression(parent) && comparisons.has(parent.operatorToken.kind)) return 'canonical comparison discriminant';
    if (ts.isElementAccessExpression(parent) && parent.argumentExpression === node) return 'canonical object key';
    if (ts.isCallExpression(parent) && /\.(?:closest|querySelector|querySelectorAll|matches|addClass|removeClass|toggleClass|addEventListener|removeEventListener)$/.test(parent.expression.getText(sf))) return 'DOM/Cytoscape program argument';
    if (ts.isJsxAttribute(parent) && /^(?:key|id|value|href|src|d|viewBox|fill|stroke|className|sandbox|name|type|mode|placement|data-testid)$/.test(parent.name.getText(sf))) return 'canonical JSX control/program attribute';
    if (ts.isPropertyAssignment(parent) && /^(?:boxShadow|textShadow|vertexShader|fragmentShader|background|backgroundColor|color|fill|stroke|fontFamily|fontSize|padding|margin|filter|transform)$/.test(parent.name.getText(sf))) return 'CSS/WebGL program value';
  }
  return undefined;
}
for (const file of inventory().files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json')) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8');
  const sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const bindings = new Set(sf.statements.filter(ts.isImportDeclaration).flatMap(statement => statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings) ? statement.importClause.namedBindings.elements.filter(item => ['translate', 'richText'].includes(item.propertyName?.text ?? item.name.text)).map(item => item.name.text) : []));
  const edits = [];
  function visit(node) {
    if (ts.isCallExpression(node) && bindings.has(node.expression.getText(sf)) && node.arguments[0] && ts.isStringLiteralLike(node.arguments[0])) {
      const id = node.arguments[0].text, entry = stage.messages[id], reason = canonicalContext(node, sf);
      if (entry && reason) {
        findings.push({ repo: file.repo, file: file.file, line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1, id, source: entry.message, reason });
        if (node.arguments.length === 1) { edits.push({ start: node.getStart(sf), end: node.end, replacement: JSON.stringify(entry.locations.find(item => item.source)?.source ?? entry.message) }); restored.add(id); }
        else throw new Error(`Interpolated program binding needs explicit rawCode review: ${file.file}:${findings.at(-1).line}`);
        return;
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  if (process.argv.includes('--repair') && edits.length) {
    let output = text;
    for (const edit of edits.sort((a, b) => b.start - a.start)) output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end);
    fs.writeFileSync(absolute, output);
  }
}
fs.writeFileSync(path.join(directory, 'canonical-binding-review.json'), JSON.stringify(findings, null, 2) + '\n');
console.log(JSON.stringify({ programTranslationCalls: findings.length, repaired: process.argv.includes('--repair'), findings }, null, 2));
if (findings.length && !process.argv.includes('--repair')) process.exitCode = 1;
