import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { frontend, roots, parentOwned } from './config.mjs';
import { inventory } from './inventory.mjs';
const report = [];
const ancestors = node => { const result = []; for (let p = node.parent; p; p = p.parent) result.push(p); return result; };
for (const file of inventory().files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json')) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8'), sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const edits = [], imports = new Set(), ranges = [];
  const add = (node, replacement, reason) => { if (ranges.some(([a, b]) => node.getStart(sf) >= a && node.end <= b)) return; ranges.push([node.getStart(sf), node.end]); edits.push({ start: node.getStart(sf), end: node.end, replacement, reason }); };
  const pro = file.repo === 'netcap-pro' && /\/(?:similarity|graph|MachineBuilder|MachineRunner)\.tsx$/.test(file.file);
  function display(node) {
    for (let p = node.parent; p; p = p.parent) {
      if (ts.isCallExpression(p) && /^(?:metadataText|suppliedMetadataText|metadataMessage|translate|i18nText|JSON\.stringify|rawCode)$/.test(p.expression.getText(sf))) return false;
      if (ts.isBinaryExpression(p) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken].includes(p.operatorToken.kind)) return false;
      if (ts.isStatement(p)) return false;
      if (ts.isJsxExpression(p)) return !ts.isJsxAttribute(p.parent) || /^(?:label|title|primary|secondary|data-learn|aria-label)$/.test(p.parent.name.getText(sf));
    }
    return false;
  }
  function visit(node) {
    if (ranges.some(([a, b]) => node.getStart(sf) >= a && node.end <= b)) return;
    if (ts.isPropertyAccessExpression(node)) {
      const owner = node.expression.getText(sf), field = node.name.text;
      const intermediate = ts.isPropertyAccessExpression(node.parent) && node.parent.expression === node || ts.isElementAccessExpression(node.parent) && (node.parent.expression === node || node.parent.argumentExpression === node);
      if (pro && ['similarities', 'differences', 'unavailable', 'context', 'quality', 'notices'].includes(field) && (ts.isPropertyAccessExpression(node.parent) && ['map', 'join', 'slice'].includes(node.parent.name.text) || ts.isElementAccessExpression(node.parent) && node.parent.expression === node) && display(node)) {
        imports.add('metadataTexts'); add(node, `metadataTexts(${owner}, ${JSON.stringify(field)})`, 'structured-pro-backend-message-array'); return;
      }
      if (!intermediate && display(node) && (pro && ['name', 'description', 'category', 'label', 'explanation', 'error', 'state', 'status', 'machineName', 'stepName'].includes(field)
        || /\/BPFPage\.tsx$/.test(file.file) && owner === 'example' && ['name', 'description'].includes(field)
        || /\/HarvestersPage\.tsx$/.test(file.file) && owner === 'preset' && field === 'description'
        || /\/DpiPage\.tsx$/.test(file.file) && field === 'status')) {
        imports.add('suppliedMetadataText'); add(node, `suppliedMetadataText(${owner}, ${JSON.stringify(field)})`, 'paired-ui-message-with-raw-user-data-fallback'); return;
      }
      if (field === 'message' && /^(?:result|response|res|data|transformResult)$/.test(owner)) {
        const sink = ancestors(node).find(ts.isCallExpression);
        if (sink && /^(?:set.*(?:Success|Error|Message|Snackbar|Toast|Notification|Notice)|notify|showSnackbar)$/.test(sink.expression.getText(sf))) { imports.add('metadataMessage'); add(node, `metadataMessage(${owner}, 'message')`, 'retain-backend-notification-metadata'); return; }
      }
      if (field === 'message' && /^(?:e|err|error|failure|[a-zA-Z]+Error)$/.test(owner)) {
        const sink = ancestors(node).find(parent => ts.isCallExpression(parent) && /^(?:set.*(?:Error|Message|Snackbar|Toast|Notification|Notice|Failure)|notify|showSnackbar)$/.test(parent.expression.getText(sf)));
        if (sink) { imports.add('errorText'); add(node, `errorText(${owner})`, 'retain-wails-error-cause-message'); return; }
      }
    }
    if (pro && file.file.endsWith('/pages/graph.tsx') && ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'data' && node.arguments[0] && ts.isStringLiteral(node.arguments[0]) && node.arguments[0].text === 'label' && display(node)) {
      imports.add('suppliedMetadataText'); add(node, `suppliedMetadataText(${node.expression.expression.getText(sf)}.data(), 'label')`, 'synthetic-label-presentation-with-canonical-cytoscape-data'); return;
    }
    if (file.file.endsWith('/pages/graph.tsx') && ts.isPropertyAssignment(node) && node.name.getText(sf) === 'label' && ts.isPropertyAccessExpression(node.initializer) && /^(?:entity|edge|node)$/.test(node.initializer.expression.getText(sf))) {
      const value = node.initializer.expression.getText(sf);
      const existing = ts.isObjectLiteralExpression(node.parent) && node.parent.properties.some(property => ts.isPropertyAssignment(property) && property.name.getText(sf) === 'labelI18n');
      if (!existing) edits.push({ start: node.end, end: node.end, replacement: `, labelI18n: (${value} as unknown as { labelI18n?: unknown }).labelI18n`, reason: 'preserve-backend-label-metadata-without-changing-label-or-id' });
    }
    if (file.file.endsWith('/pages/graph.tsx') && ts.isStringLiteral(node) && node.text === 'data(label)' && ancestors(node).some(parent => ts.isPropertyAssignment(parent) && parent.name.getText(sf) === 'label')) { imports.add('GRAPH:graphLabel'); add(node, 'graphLabel', 'display-only-cytoscape-label-formatter'); return; }
    if (file.file.endsWith('/pages/graph.tsx') && ts.isFunctionDeclaration(node) && node.name && /^[A-Z]/.test(node.name.text) && node.body?.getText(sf).includes('const __uiLocale =')) {
      const pointer = node.body.statements.find(statement => statement.getText(sf).includes('useRef') && /cyRef|cytoscapeRef/.test(statement.getText(sf)));
      if (pointer && !node.body.getText(sf).includes('updateGraphLocale(cyRef.current)')) {
        imports.add('GRAPH:updateGraphLocale');
        edits.push({ start: pointer.end, end: pointer.end, replacement: `\n  useEffect(() => { updateGraphLocale(cyRef.current); }, [__uiLocale]);\n`, reason: 'redraw-localized-labels-preserving-graph-selection-and-viewport' });
      }
    }
    // Custom protobuf names are user content, even if they match a built-in field.
    if (file.file.endsWith('/ProtobufPage.tsx') && ts.isCallExpression(node) && /^(?:fieldLabel|recordTypeLabel)$/.test(node.expression.getText(sf)) && node.arguments[0]?.getText(sf).startsWith('f.')) { add(node, node.arguments[0].getText(sf), 'preserve-user-protobuf-identifiers'); return; }
    if (file.file.endsWith('/ChartConfigDialog.tsx') && ts.isCallExpression(node) && node.expression.getText(sf) === 'fieldLabel' && node.arguments.length === 1) { edits.push({ start: node.arguments[0].end, end: node.arguments[0].end, replacement: ', auditType', reason: 'do-not-relabel-unknown-custom-schema-fields' }); }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  if (!edits.length) continue;
  const statements = sf.statements.filter(ts.isImportDeclaration), bound = new Set(statements.flatMap(statement => statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings) ? statement.importClause.namedBindings.elements.map(item => item.name.text) : []));
  const required = [...imports].filter(name => !bound.has(name.replace(/^GRAPH:/, '')));
  let module = path.posix.relative(path.posix.dirname(file.file), file.repo === 'netcap-pro' ? 'frontend/src/lib/i18n' : 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n'); if (!module.startsWith('.')) module = './' + module;
  const position = statements.at(-1)?.end ?? sf.statements[0]?.getStart(sf) ?? 0, declarations = [];
  if (required.some(name => !name.startsWith('GRAPH:'))) declarations.push(`import { ${required.filter(name => !name.startsWith('GRAPH:')).join(', ')} } from ${JSON.stringify(module)};`);
  if (required.some(name => name.startsWith('GRAPH:'))) declarations.push(`import { ${required.filter(name => name.startsWith('GRAPH:')).map(name => name.slice(6)).join(', ')} } from '../lib/graphPresentation';`);
  if (declarations.length) edits.push({ start: position, end: position, replacement: '\n' + declarations.join('\n') + '\n', reason: 'backend-presentation-imports' });
  let output = text, boundary = text.length;
  for (const edit of edits.sort((a, b) => b.start - a.start)) { if (edit.end > boundary) throw new Error(`Overlapping backend bindings: ${file.file}`); output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end); boundary = edit.start; }
  fs.writeFileSync(absolute, output); report.push({ file: file.file, edits: edits.map(({ start, reason }) => ({ line: sf.getLineAndCharacterOfPosition(start).line + 1, reason })) });
}
fs.writeFileSync(path.join(frontend, 'localization/backend-bindings.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ files: report.length }));
