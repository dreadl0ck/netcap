import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { frontend, roots, parentOwned, namespaceFor } from './config.mjs';
import { inventory, stableKey, escapeICU } from './inventory.mjs';

const snapshot = inventory(), stagePath = path.join(frontend, 'localization/full-staging.json');
const stage = JSON.parse(fs.readFileSync(stagePath, 'utf8'));
const changes = [];
const css = /^(?:rgba?\(|hsla?\(|linear-gradient|radial-gradient|var\(|calc\(|[\d.]+(?:px|rem|vh|vw)|\d+px |#[a-f\d]{3,8}$)|(?:^|\s)(?:solid|monospace|sans-serif|ease-in-out|cubic-bezier)(?:\s|$)/i;
const technical = new Set(['PCAP', 'PCAPNG', 'HTTP', 'HTTPS', 'TCP', 'UDP', 'DNS', 'TLS', 'IPv4', 'IPv6', 'IP', 'MAC', 'ID', 'CVE', 'CPE', 'JSON', 'CSV', 'YAML', 'XML', 'HTML', 'ns', 'µs', 'ms', 's', 'min', 'h', 'd', 'B', 'KB', 'MB', 'GB', 'KiB', 'MiB', 'GiB', 'UTC', 'true', 'false', 'null', 'undefined']);
const singleUI = /^(?:Unknown|Unavailable|Available|Loading[.…]*|Working|Connected|Disconnected|Reconnecting[.…]*|Checking[.…]*|Default|Enabled|Disabled|None|Never|Yes|No|Untitled|untagged|unavailable|unknown|optional|Required|Optional|Verified|Legacy|Pending)$/;
const prose = value => typeof value === 'string' && /\p{L}/u.test(value) && !technical.has(value.trim()) && !css.test(value) && (/\s/.test(value.trim()) || singleUI.test(value.trim())) && !/^(?:https?:|wss?:|\/|\.\/|\.\.\/|@|<\/?(?:span|div|svg|path|style)\b|data\(|[A-Za-z][A-Za-z\d]*\.[A-Za-z\d]+\b)/.test(value.trim()) && !/[;{}]\s*(?:return|const|let|function|float|vec[234])\b/.test(value);
const parentList = node => { const result = []; for (let p = node.parent; p; p = p.parent) result.push(p); return result; };
const nameOf = node => node && (ts.isIdentifier(node) || ts.isStringLiteral(node)) ? node.text : '';
const metadataFields = new Set(['label', 'title', 'description', 'question', 'caption', 'tooltip', 'helperText', 'placeholder', 'primary', 'secondary', 'displayName', 'name', 'category']);
const canonicalProps = new Set(['path', 'href', 'url', 'id', 'key', 'type', 'field', 'value', 'inputTypes', 'outputTypes', 'style', 'sx', 'color', 'border', 'boxShadow', 'fontFamily', 'fontSize', 'content', 'background', 'filter', 'transition', 'animation', 'gridTemplateColumns']);

for (const file of snapshot.files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json') || /\/(?:i18n|appearance|graphAppearance|theme|graphLayout|replay|timelineTime|bpfSyntaxHighlight|filterSyntaxHighlight|regexSyntaxHighlight|html|recordUnits)\./.test(file.file) || /\/(?:Preferences|PresentationControls|AppearanceControls)/.test(file.file)) continue;
  const absolute = path.join(roots[file.repo], file.file), source = fs.readFileSync(absolute, 'utf8');
  const sf = ts.createSourceFile(file.file, source, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const edits = [], imports = new Set(), consumed = [];
  const occurrences = new Map(file.occurrences.map(item => [item.start, item]));
  const isConsumed = node => consumed.some(([start, end]) => node.getStart(sf) >= start && node.end <= end);
  const edit = (node, replacement, reason) => { if (isConsumed(node)) return; edits.push({ start: node.getStart(sf), end: node.end, replacement, reason }); consumed.push([node.getStart(sf), node.end]); };
  function keyFor(node, message, sourceText = message) {
    let namespace = namespaceFor(file.file, sourceText);
    const method = parentList(node).find(ts.isMethodDeclaration);
    if (method && /(?:DPI|Database|GeoProvider|YARA|Injection|Signature)/i.test(nameOf(method.name))) namespace = 'removed';
    const key = stableKey(message), qualified = `${namespace}:${key}`;
    stage.messages[qualified] ??= { namespace, key, message, context: '', locations: [] };
    stage.messages[qualified].locations.push({ repo: file.repo, file: file.file, line: sf.getLineAndCharacterOfPosition(node.getStart()).line + 1, source: sourceText });
    return qualified;
  }
  function literal(node, deferred = false) {
    imports.add(deferred ? 'message' : 'translate');
    if (ts.isStringLiteralLike(node)) return `${deferred ? 'message' : 'translate'}(${JSON.stringify(keyFor(node, escapeICU(node.text), node.text))})`;
    const values = node.templateSpans.map((span, index) => `arg${index}: ${span.expression.getText(sf)}`);
    let pattern = escapeICU(node.head.text);
    node.templateSpans.forEach((span, index) => { pattern += `{arg${index}}${escapeICU(span.literal.text)}`; });
    return `${deferred ? 'message' : 'translate'}(${JSON.stringify(keyFor(node, pattern))}, { ${values.join(', ')} })`;
  }
  function deferred(node) {
    if (ts.isStringLiteralLike(node) && prose(node.text) || ts.isTemplateExpression(node) && prose(node.head.text + node.templateSpans.map(span => span.literal.text).join(' '))) return literal(node, true);
    if (ts.isBinaryExpression(node) && [ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken].includes(node.operatorToken.kind)) return `${node.left.getText(sf)} ${node.operatorToken.getText(sf)} ${deferred(node.right)}`;
    if (ts.isConditionalExpression(node)) return `${node.condition.getText(sf)} ? ${deferred(node.whenTrue)} : ${deferred(node.whenFalse)}`;
    return node.getText(sf);
  }
  function visit(node) {
    if (isConsumed(node)) return;
    if (ts.isCallExpression(node) && node.expression.getText(sf) === 'i18nText' && node.arguments[0]) {
      const value = node.arguments[0].getText(sf);
      if (['current', 'factId', 'iconMap[iconName]'].includes(value)) { edit(node, value, 'preserve-version-evidence-or-component-identity'); return; }
    }
    if (ts.isNewExpression(node) && node.expression.getText(sf) === 'Error' && node.arguments?.[0] && !/\/(?:contexts|providers)\//.test(file.file)) {
      const argument = node.arguments[0];
      const replacement = deferred(argument);
      if (replacement !== argument.getText(sf)) { imports.add('displayError'); edit(node, `displayError(${replacement}${node.arguments[1] ? ', ' + node.arguments[1].getText(sf) : ''})`, 'deferred-app-error-with-english-diagnostic'); return; }
    }
    if (ts.isCallExpression(node) && /^set.*(?:Error|Failure)$/.test(node.expression.getText(sf)) && node.arguments[0]) {
      const argument = node.arguments[0];
      let target;
      if (ts.isPropertyAccessExpression(argument) && argument.name.text === 'message') target = argument.expression;
      if (ts.isCallExpression(argument) && argument.expression.getText(sf) === 'String' && argument.arguments[0] && /^(?:err|error|e|failure)$/i.test(argument.arguments[0].getText(sf))) target = argument.arguments[0];
      if (target) { imports.add('errorText'); edit(argument, `errorText(${target.getText(sf)})`, 'retain-error-message-descriptor'); return; }
    }
    if ((ts.isStringLiteralLike(node) || ts.isTemplateExpression(node)) && !parentList(node).some(p => ts.isImportDeclaration(p) || ts.isExportDeclaration(p) || ts.isLiteralTypeNode(p))) {
      const text = ts.isTemplateExpression(node) ? node.head.text + node.templateSpans.map(span => span.literal.text).join(' ') : node.text;
      if (!prose(text)) { ts.forEachChild(node, visit); return; }
      const chain = parentList(node), occurrence = occurrences.get(node.getStart(sf));
      const property = chain.find(ts.isPropertyAssignment), propertyName = property ? nameOf(property.name) : '';
      const cssContext = chain.some(p => ts.isJsxAttribute(p) && /^(?:sx|style|anchorOrigin|flexDirection|fontFamily|animation|transition)$/.test(p.name.getText(sf))) || chain.some(p => ts.isTaggedTemplateExpression(p)) || chain.some(p => ts.isVariableDeclaration(p) && /(?:_SX|_STYLE|Style|Styles|Palette|COLORS|PALETTE|SHADER|Shader)$/.test(p.name.getText(sf))) || canonicalProps.has(propertyName);
      const call = chain.find(ts.isCallExpression), callee = call?.expression.getText(sf) ?? '';
      if (cssContext || /^(?:i18nText|i18nRichText|i18nMessage|translate|richText|message)$/.test(callee) || /^(?:console|logger|log)\./.test(callee) || /(?:^|\.)(?:fetch|replace|replaceAll|split|join|includes|startsWith|endsWith|match|test|querySelector|querySelectorAll|setAttribute|setItem|getItem|addEventListener|On|Emit)$/.test(callee)) { ts.forEachChild(node, visit); return; }
      if (occurrence?.classification === 'canonical' && occurrence.reason !== 'jsx-prop:onClick') { ts.forEachChild(node, visit); return; }
      if (ts.isCaseClause(node.parent) && node.parent.expression === node || ts.isAsExpression(node.parent)) return;
      if (property && metadataFields.has(propertyName) || ts.isArrayLiteralExpression(node.parent)) {
        keyFor(node, ts.isTemplateExpression(node) ? occurrence.message : escapeICU(node.text), ts.isTemplateExpression(node) ? occurrence.source : node.text);
        // Data/metadata identity stays canonical. Its UI binding owns translation.
        return;
      }
      const parameter = chain.find(ts.isParameter);
      if (parameter && (parameter.initializer === node || ts.isBindingElement(node.parent) && node.parent.initializer === node)) { edit(node, literal(node), 'component-default-display-text'); return; }
      const returns = chain.find(ts.isReturnStatement), variable = chain.find(ts.isVariableDeclaration);
      const functionAncestor = chain.find(p => ts.isFunctionDeclaration(p) || ts.isArrowFunction(p) || ts.isFunctionExpression(p) || ts.isMethodDeclaration(p));
      const messageVariable = variable && /(?:label|title|question|tooltip|hint|description|message|notice|gated|placeholder|text|summary)$/i.test(variable.name.getText(sf));
      if (functionAncestor && (returns || messageVariable)) { const value = literal(node); edit(node, ts.isJsxAttribute(node.parent) ? `{${value}}` : value, 'runtime-authored-display-expression'); return; }
      // Static diagnostic sources are registered and resolved only at error UI sinks.
      if (occurrence?.reason === 'error-may-reach-ui') keyFor(node, occurrence.message, occurrence.source);
    }
    if (ts.isPropertyAccessExpression(node)) {
      const owner = node.expression.getText(sf), field = node.name.text;
      const isDisplay = (() => { for (let p = node.parent; p; p = p.parent) { if (ts.isCallExpression(p) && /^(?:i18nText|translate|metadataText)$/.test(p.expression.getText(sf))) return false; if (ts.isJsxExpression(p)) return !ts.isJsxAttribute(p.parent) || /^(?:title|label|primary|secondary|data-learn|aria-label)$/.test(p.parent.name.getText(sf)); if (ts.isStatement(p)) return false; } return false; })();
      const staticMetadata = /\/(?:ChartConfigDialog|DashboardChartTile|ExplorePage|graph|MachineBuilder|WhatsNewDialog)\.tsx$/.test(file.file) && /^(?:ct|chartType|type|option|view|securityView|selectedView|transform|t|layout|highlight|item)$/.test(owner) && ['label', 'description', 'question', 'title', 'name', 'category'].includes(field);
      if (isDisplay && staticMetadata) { imports.add('translate'); edit(node, `translate(${node.getText(sf)})`, 'registered-app-metadata-display-binding'); return; }
      if (isDisplay && field === 'message' && /^(?:err|error|[a-zA-Z]*Error)$/.test(owner)) { imports.add('renderError'); edit(node, `renderError(${owner})`, 'structured-error-display'); return; }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  if (!edits.length) continue;
  let module = file.repo === 'netcap-pro' ? path.posix.relative(path.posix.dirname(file.file), 'frontend/src/lib/i18n') : path.posix.relative(path.posix.dirname(file.file), 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n');
  if (!module.startsWith('.')) module = './' + module;
  if (imports.size) {
    const existing = sf.statements.filter(ts.isImportDeclaration), start = existing.at(-1)?.end ?? sf.statements[0]?.getStart(sf) ?? 0;
    edits.push({ start, end: start, replacement: `\nimport { ${[...imports].join(', ')} } from ${JSON.stringify(module)};\n`, reason: 'localization-imports' });
  }
  let output = source, boundary = source.length;
  for (const edit of edits.sort((a, b) => b.start - a.start)) {
    if (edit.end > boundary) throw new Error(`Overlapping residual migrations: ${file.file}`);
    output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end); boundary = edit.start;
  }
  const parsed = ts.createSourceFile(file.file, output, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  if (parsed.parseDiagnostics.length) {
    fs.writeFileSync('/var/folders/sb/n7njgj0s1ln8wkb4j9hs4n8h0000gn/T/opencode/netcap-i18n-refine-failed.tsx', output);
    fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
    throw new Error(`Invalid refined syntax: ${file.file}: ${parsed.parseDiagnostics.map(item => `${parsed.getLineAndCharacterOfPosition(item.start).line + 1}: ${ts.flattenDiagnosticMessageText(item.messageText, ' ')}`).join('; ')}`);
  }
  fs.writeFileSync(absolute, output);
  fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
  changes.push({ repo: file.repo, file: file.file, edits: edits.map(edit => ({ line: sf.getLineAndCharacterOfPosition(edit.start).line + 1, reason: edit.reason })) });
}
fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
fs.writeFileSync(path.join(frontend, 'localization/residual-migration.json'), JSON.stringify(changes, null, 2) + '\n');
console.log(JSON.stringify({ changedFiles: changes.length, messages: Object.keys(stage.messages).length }));
