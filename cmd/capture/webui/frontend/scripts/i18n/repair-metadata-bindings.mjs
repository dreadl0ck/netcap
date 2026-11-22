import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { frontend, roots, parentOwned } from './config.mjs';
import { inventory } from './inventory.mjs';
let files = 0, count = 0;
for (const file of inventory().files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json')) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8'), sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  if (process.argv.includes('--pro-final') && file.file !== 'frontend/src/pages/similarity.tsx') continue;
  const edits = [], imports = new Set();
  const replace = (node, replacement) => edits.push({ start: node.getStart(sf), end: node.end, replacement });
  function visit(node) {
    if (file.file === 'frontend/src/pages/similarity.tsx') {
      if (ts.isCallExpression(node) && node.expression.getText(sf) === 'metadataTexts' && node.arguments[0] && ts.isCallExpression(node.arguments[0]) && node.arguments[0].expression.getText(sf) === 'suppliedMetadataText' && node.arguments[0].arguments[1]?.getText(sf).replace(/["']/g, '') === 'explanation') {
        replace(node.arguments[0], `${node.arguments[0].arguments[0].getText(sf)}.explanation`); return;
      }
      if (ts.isElementAccessExpression(node) && node.expression.getText(sf) === 'groupLabels') {
        imports.add('SIMILARITY:similarityGroupLabel'); const key = node.argumentExpression.getText(sf);
        replace(node, `similarityGroupLabel(${key}${key === 'group.name' ? ', group' : ''})`); return;
      }
      if (ts.isPropertyAccessExpression(node) && ts.isSpreadElement(node.parent) && ['quality', 'unavailable'].includes(node.name.text)) {
        imports.add('metadataTexts'); replace(node, `metadataTexts(${node.expression.getText(sf)}, '${node.name.text}')`); return;
      }
      if (ts.isJsxExpression(node) && node.expression && ts.isConditionalExpression(node.expression) && node.expression.condition.getText(sf) === 'ready' && !node.getText(sf).includes('presentationValue')) {
        imports.add('presentationValue'); replace(node.expression, `<>{presentationValue(status, 'state') && <Box component="span" display="block" role="status">{suppliedMetadataText(status, 'state')}</Box>}{${node.expression.getText(sf)}}</>`); return;
      }
      if (ts.isJsxElement(node) && node.openingElement.tagName.getText(sf) === 'TableCell' && node.children.some(child => ts.isJsxExpression(child) && child.expression?.getText(sf) === 'suppliedMetadataText(metric, "label")') && !node.openingElement.attributes.properties.some(attribute => ts.isJsxAttribute(attribute) && attribute.name.getText(sf) === 'title')) edits.push({ start: node.openingElement.attributes.end, end: node.openingElement.attributes.end, replacement: ` title={suppliedMetadataText(metric, 'explanation')}` });
      if (ts.isCallExpression(node) && node.expression.getText(sf) === 'String' && node.arguments[0]?.getText(sf) === 'statusError') { imports.add('renderError'); replace(node, 'renderError(statusError)'); return; }
      if (ts.isCallExpression(node) && node.expression.getText(sf) === 'JSON.stringify' && node.arguments[0]?.getText(sf) === 'JSON.parse(value)') { imports.add('formatEvidenceJSON'); replace(node, 'formatEvidenceJSON(value)'); return; }
      if (ts.isObjectLiteralExpression(node) && node.properties.some(property => ts.isPropertyAssignment(property) && property.name.getText(sf) === 'id' && property.initializer.getText(sf) === "'balanced'") && node.properties.some(property => ts.isPropertyAssignment(property) && property.name.getText(sf) === 'name') && !node.properties.some(property => ts.isPropertyAssignment(property) && property.name.getText(sf) === 'nameI18n')) edits.push({ start: node.end - 1, end: node.end - 1, replacement: `, nameI18n: { id: 'direct:pro.similarity.profile.balanced.name', text: 'Balanced behavior' }` });
    }
    if (ts.isCallExpression(node) && node.expression.getText(sf) === 'suppliedMetadataText' && node.arguments.length >= 2 && ts.isStringLiteral(node.arguments[1])) {
      const member = ts.isPropertyAccessExpression(node.parent) && node.parent.expression === node ? node.parent.name.text : null;
      const structural = member && !['toUpperCase', 'toLowerCase', 'trim', 'split', 'substring', 'slice', 'replace', 'includes', 'startsWith', 'endsWith'].includes(member);
      const key = ts.isElementAccessExpression(node.parent) && node.parent.argumentExpression === node;
      if (structural || key) { edits.push({ start: node.getStart(sf), end: node.end, replacement: `${node.arguments[0].getText(sf)}.${node.arguments[1].text}` }); return; }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  if (imports.size) {
    const declarations = sf.statements.filter(ts.isImportDeclaration), bound = new Set(declarations.flatMap(statement => statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings) ? statement.importClause.namedBindings.elements.map(item => item.name.text) : []));
    const needed = [...imports].filter(name => !bound.has(name.replace('SIMILARITY:', ''))), lines = [];
    if (needed.some(name => !name.startsWith('SIMILARITY:'))) lines.push(`import { ${needed.filter(name => !name.startsWith('SIMILARITY:')).join(', ')} } from '../lib/i18n';`);
    if (needed.includes('SIMILARITY:similarityGroupLabel')) lines.push(`import { similarityGroupLabel } from '../lib/similarity';`);
    const position = declarations.at(-1)?.end ?? 0;
    if (lines.length) edits.push({ start: position, end: position, replacement: '\n' + lines.join('\n') + '\n' });
  }
  let output = text;
  for (const edit of edits.sort((a, b) => b.start - a.start)) output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end);
  if (edits.length) { fs.writeFileSync(absolute, output); files++; count += edits.length; }
}
console.log(JSON.stringify({ files, structuralReadsPreserved: count }));
