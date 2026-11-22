import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { frontend, roots, parentOwned, namespaceFor } from './config.mjs';
import { inventory, stableKey, escapeICU } from './inventory.mjs';
const stagePath = path.join(frontend, 'localization/full-staging.json'), stage = JSON.parse(fs.readFileSync(stagePath, 'utf8')), report = [];
const technical = new Set(['MITRE ATT&CK', 'CISA KEV', 'HTTP', 'HTTPS', 'TCP', 'UDP', 'DNS', 'DHCP', 'SNI', 'DPI', 'PCAP', 'PCAPs', 'YARA', 'YARA-X', 'GeoIP', 'JSON', 'CSV', 'XML', 'SHA256', 'SHA-256', 'MD5', 'TLS']);
const canonicalProps = new Set(['id', 'key', 'path', 'href', 'name', 'value', 'type', 'field', 'severity', 'variant', 'color', 'size', 'state', 'status', 'mode', 'component', 'align', 'role', 'scope']);
const helperCalls = /^(?:i18nText|i18nRichText|i18nMessage|translate|message|richText|metadataText|suppliedMetadataText|metadataMessage|metadataTexts|presentationValue|rawCode|i18nParameterMessage|i18nParameterText)$/;
const parents = node => { const result = []; for (let p = node.parent; p; p = p.parent) result.push(p); return result; };
for (const file of inventory().files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json') || /\/(?:Preferences|AppearanceControls|PresentationControls)/.test(file.file)) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8'), sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const edits = [], needed = new Set(), ranges = [];
  const add = (node, replacement, reason) => { if (ranges.some(([a, b]) => node.getStart() >= a && node.end <= b)) return; ranges.push([node.getStart(), node.end]); edits.push({ start: node.getStart(sf), end: node.end, replacement, reason }); };
  function make(node, deferred = false) {
    const values = []; let source;
    if (ts.isStringLiteralLike(node)) source = node.text;
    else if (ts.isTemplateExpression(node)) { source = node.head.text; node.templateSpans.forEach((span, index) => { source += `{arg${index}}${span.literal.text}`; values.push(`arg${index}: ${span.expression.getText(sf)}`); }); }
    else return node.getText(sf);
    let pattern = ts.isStringLiteralLike(node) ? escapeICU(source) : escapeICU(node.head.text);
    if (ts.isTemplateExpression(node)) node.templateSpans.forEach((span, index) => { pattern += `{arg${index}}${escapeICU(span.literal.text)}`; });
    const namespace = namespaceFor(file.file, source), key = stableKey(pattern), id = `${namespace}:${key}`;
    stage.messages[id] ??= { namespace, key, message: pattern, context: '', locations: [{ repo: file.repo, file: file.file, line: sf.getLineAndCharacterOfPosition(node.getStart()).line + 1, source }] };
    const fn = deferred ? 'finalCopyMessage' : 'finalCopyText'; needed.add(deferred ? 'message as finalCopyMessage' : 'translate as finalCopyText');
    return `${fn}(${JSON.stringify(id)}${values.length ? ', { ' + values.join(', ') + ' }' : ''})`;
  }
  function visit(node) {
    if (ranges.some(([a, b]) => node.getStart() >= a && node.end <= b)) return;
    if (ts.isCallExpression(node) && node.expression.getText(sf) === 'describeFailure' && node.arguments[1] && ts.isStringLiteralLike(node.arguments[1])) { add(node.arguments[1], make(node.arguments[1], true), 'deferred-http-failure-fallback'); return; }
    if (file.file.endsWith('/components/LicenseGate.tsx') && ts.isStringLiteral(node) && !ts.isBinaryExpression(node.parent) && parents(node).some(parent => ts.isVariableDeclaration(parent) && parent.name.getText(sf) === 'heading')) { add(node, make(node), 'direct-edition-runtime-heading'); return; }
    if (file.file.endsWith('/components/TrafficScene.tsx') && ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'onError' && node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0])) { add(node, `${node.expression.getText(sf)}(${node.arguments[0].getText(sf)}, ${make(node.arguments[0], true)})`, 'additive-scene-error-presentation'); return; }
    if (file.file.endsWith('/pages/traffic-3d.tsx') && ts.isJsxAttribute(node) && node.name.getText(sf) === 'onError' && node.initializer && ts.isJsxExpression(node.initializer) && node.initializer.expression?.getText(sf) === 'setSceneError') { add(node.initializer, '{(diagnostic, presentation) => setSceneError(presentation ?? diagnostic)}', 'retain-scene-error-descriptor'); return; }
    if (ts.isJsxAttribute(node) && node.name.getText(sf) === 'learnHint' && node.initializer) {
      const value = ts.isJsxExpression(node.initializer) ? node.initializer.expression : node.initializer;
      if (value && (ts.isStringLiteralLike(value) || ts.isTemplateExpression(value))) { add(node.initializer, `{${make(value, true)}}`, 'reactive-learn-hint-without-module-time-translation'); return; }
    }
    if (ts.isJsxAttribute(node) && node.name.getText(sf) === 'data-learn' && node.initializer && ts.isJsxExpression(node.initializer) && node.initializer.expression?.getText(sf) === 'learnHint') { needed.add('renderText'); add(node.initializer.expression, 'renderText(learnHint)', 'resolve-supplied-hint-descriptor'); return; }
    if (ts.isStringLiteralLike(node) || ts.isTemplateExpression(node)) {
      const chain = parents(node), attribute = chain.find(ts.isJsxAttribute);
      const value = ts.isTemplateExpression(node) ? node.head.text + node.templateSpans.map(span => span.literal.text).join('') : node.text;
      const bound = chain.find(ts.isCallExpression);
      const directArg = bound?.arguments.some(argument => argument === node);
      const key = ts.isPropertyAssignment(node.parent) && canonicalProps.has(node.parent.name.getText(sf));
      const comparison = ts.isBinaryExpression(node.parent) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken].includes(node.parent.operatorToken.kind);
      const inlineFallback = !attribute && chain.some(ts.isJsxExpression) && ts.isStringLiteralLike(node) && new Set(['N/A', 'Unknown', 'Unavailable', '(default)', 'Success', 'Refused']).has(node.text) && !chain.some(parent => ts.isCallExpression(parent) && /^(?:JSON\.stringify|rawCode)$/.test(parent.expression.getText(sf)));
      const ui = attribute && /^(?:label|title|placeholder|helperText|aria-label|aria-description|data-learn)$/.test(attribute.name.getText(sf)) || inlineFallback;
      if (ui && /[A-Za-z]{3}/.test(value) && !technical.has(value.trim()) && !key && !comparison && !directArg && !chain.some(ts.isArrayLiteralExpression) && !(bound && helperCalls.test(bound.expression.getText(sf))) && !/^(?:[/@#]|https?:|rgba?\(|var\(|[a-z][a-z0-9_]*\(|[A-Za-z_][A-Za-z0-9_.]*\s*(?:==|!=|>=|<=))/.test(value)) {
        if (ts.isStringLiteralLike(node) && ts.isPropertyAssignment(node.parent) && node.parent.name === node) return;
        add(node, ts.isJsxAttribute(node.parent) ? `{${make(node)}}` : make(node), 'inspected-ui-expression-leaf-not-control-id'); return;
      }
    }
    if (file.file.endsWith('/components/DatabaseBootstrap.tsx') && ts.isTemplateExpression(node) && node.head.text === 'Downloading ' && !parents(node).some(parent => ts.isCallExpression(parent) && helperCalls.test(parent.expression.getText(sf)))) { add(node, make(node), 'download-progress-prose'); return; }
    if (file.file.endsWith('/pages/DbsPage.tsx') && ts.isElementAccessExpression(node) && node.expression.getText(sf) === 'DB_DESCRIPTIONS') { needed.add('translate as finalCopyText'); add(node, `finalCopyText(${node.getText(sf)})`, 'known-database-documentation-registry'); return; }
    if (file.file.endsWith('/pages/DbsPage.tsx') && ts.isStringLiteral(node) && ts.isPropertyAssignment(node.parent) && ts.isObjectLiteralExpression(node.parent.parent) && parents(node).some(parent => ts.isVariableDeclaration(parent) && parent.name.getText(sf) === 'DB_DESCRIPTIONS')) { make(node); }
    if (ts.isElementAccessExpression(node) && node.expression.getText(sf) === 'linkKindLabels' && parents(node).some(ts.isJsxExpression)) { needed.add('translate as finalCopyText'); add(node, `finalCopyText(${node.getText(sf)})`, 'known-evidence-link-kind-label'); return; }
    if (file.file.endsWith('/lib/evidenceLinks.ts') && ts.isStringLiteral(node) && ts.isPropertyAssignment(node.parent) && parents(node).some(parent => ts.isVariableDeclaration(parent) && parent.name.getText(sf) === 'linkKindLabels')) { make(node); }
    if (file.file.endsWith('/pages/SecretsPage.tsx') && ts.isStringLiteral(node) && ts.isPropertyAssignment(node.parent) && /^(?:userLabel|passLabel)$/.test(node.parent.name.getText(sf)) && node.text) { make(node); }
    if (file.file.endsWith('/components/NetworkDetectionEvidence.tsx') && ts.isStringLiteral(node) && parents(node).some(parent => ts.isVariableDeclaration(parent) && parent.name.getText(sf) === 'rows') && /\s/.test(node.text.trim())) { make(node); }
    if (file.file.endsWith('/lib/replay.ts') && ts.isNewExpression(node) && node.expression.getText(sf) === 'Error' && node.arguments?.[0] && ts.isTemplateExpression(node.arguments[0])) { needed.add('displayError'); add(node, `displayError(${make(node.arguments[0], true)})`, 'localized-cidr-validation-with-raw-address-param'); return; }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  if (!edits.length) continue;
  const imports = sf.statements.filter(ts.isImportDeclaration), bound = new Set(imports.flatMap(statement => statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings) ? statement.importClause.namedBindings.elements.map(item => item.name.text) : []));
  const names = [...needed].filter(name => !bound.has(name.split(' as ').at(-1)));
  if (names.length) {
    let module = path.posix.relative(path.posix.dirname(file.file), file.repo === 'netcap-pro' ? 'frontend/src/lib/i18n' : 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n'); if (!module.startsWith('.')) module = './' + module;
    const position = imports.at(-1)?.end ?? sf.statements[0]?.getStart(sf) ?? 0;
    edits.push({ start: position, end: position, replacement: `\nimport { ${names.join(', ')} } from ${JSON.stringify(module)};\n`, reason: 'final-copy-imports' });
  }
  let output = text, boundary = text.length;
  for (const edit of edits.sort((a, b) => b.start - a.start)) { if (edit.end > boundary) throw new Error(`Overlapping final copy: ${file.file}`); output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end); boundary = edit.start; }
  fs.writeFileSync(absolute, output); report.push({ file: file.file, edits: edits.map(({ start, reason }) => ({ line: sf.getLineAndCharacterOfPosition(start).line + 1, reason })) });
}
fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
fs.writeFileSync(path.join(frontend, 'localization/final-copy-migration.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ files: report.length, messages: Object.keys(stage.messages).length }));
