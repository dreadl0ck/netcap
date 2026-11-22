import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { frontend, roots, parentOwned, namespaceFor } from './config.mjs';
import { inventory, stableKey, escapeICU } from './inventory.mjs';
const snapshot = inventory(), stagePath = path.join(frontend, 'localization/full-staging.json'), stage = JSON.parse(fs.readFileSync(stagePath, 'utf8'));
const report = [];
const parentList = node => { const result = []; for (let p = node.parent; p; p = p.parent) result.push(p); return result; };
const human = value => /[A-Za-z]{3}/.test(value) && (/\s/.test(value.trim()) || /^(?:Unknown|Unavailable|Working|Loading|Ready|Yes|No|unknown|unavailable|untagged)$/.test(value)) && !/^(?:https?:|\/|@|<\/?[A-Za-z]|rgba?\(|var\(|calc\(|\d+(?:px|rem)|#)/.test(value) && !/\b(?:solid|monospace|sans-serif|vec[234]|gl_Position|ease-in-out)\b/.test(value);
function moduleFor(file) { let result = path.posix.relative(path.posix.dirname(file.file), file.repo === 'netcap-pro' ? 'frontend/src/lib/i18n' : 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n'); return result.startsWith('.') ? result : './' + result; }
for (const file of snapshot.files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json') || /\/(?:Preferences|AppearanceControls|PresentationControls)/.test(file.file) || /(?:SyntaxHighlight|\/html\.ts|appearance|theme\.ts|\/graphLayout\.ts)/.test(file.file)) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8');
  const sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const edits = [], used = new Set(), ranges = [], messageStates = new Map(), notifier = new Map();
  const imported = new Set(sf.statements.filter(ts.isImportDeclaration).flatMap(statement => statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings) ? statement.importClause.namedBindings.elements.map(item => item.name.text) : []));
  const use = name => { if (!imported.has(name)) used.add(name); return name; };
  const edit = (node, replacement, reason) => { const start = node.getStart(sf); if (ranges.some(([a, b]) => start >= a && node.end <= b)) return; ranges.push([start, node.end]); edits.push({ start, end: node.end, replacement, reason }); };
  const keyFor = (node, pattern, source = pattern) => {
    const namespace = namespaceFor(file.file, source), key = stableKey(pattern), id = `${namespace}:${key}`;
    stage.messages[id] ??= { namespace, key, message: pattern, context: '', locations: [] };
    stage.messages[id].locations.push({ repo: file.repo, file: file.file, line: sf.getLineAndCharacterOfPosition(node.getStart()).line + 1, source });
    return id;
  };
  function make(node, deferred = false) {
    if (ts.isStringLiteralLike(node)) return human(node.text) ? `${use(deferred ? 'message' : 'translate')}(${JSON.stringify(keyFor(node, escapeICU(node.text), node.text))})` : node.getText(sf);
    if (ts.isTemplateExpression(node)) {
      if (!human(node.head.text + node.templateSpans.map(span => span.literal.text).join(' '))) return node.getText(sf);
      let pattern = escapeICU(node.head.text);
      node.templateSpans.forEach((span, index) => { pattern += `{arg${index}}${escapeICU(span.literal.text)}`; });
      return `${use(deferred ? 'message' : 'translate')}(${JSON.stringify(keyFor(node, pattern))}, { ${node.templateSpans.map((span, index) => `arg${index}: ${span.expression.getText(sf)}`).join(', ')} })`;
    }
    if (ts.isConditionalExpression(node)) return `${node.condition.getText(sf)} ? ${make(node.whenTrue, deferred)} : ${make(node.whenFalse, deferred)}`;
    if (ts.isBinaryExpression(node) && [ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken].includes(node.operatorToken.kind)) return `${node.left.getText(sf)} ${node.operatorToken.getText(sf)} ${make(node.right, deferred)}`;
    return node.getText(sf);
  }
  function collect(node) {
    if (ts.isVariableDeclaration(node) && ts.isArrayBindingPattern(node.name) && node.initializer && ts.isCallExpression(node.initializer) && /^(?:React\.)?useState$/.test(node.initializer.expression.getText(sf))) {
      const [value, setter] = node.name.elements, name = value?.name?.getText(sf), set = setter?.name?.getText(sf), type = node.initializer.typeArguments?.[0];
      const initial = node.initializer.arguments[0];
      if (name && set && (type?.kind === ts.SyntaxKind.StringKeyword || type && /^(?:string\s*\|\s*null|null\s*\|\s*string)$/.test(type.getText(sf)) || !type && initial && ts.isStringLiteralLike(initial))) {
        const setters = [], references = []; let input = false;
        function scan(child) {
          if (ts.isCallExpression(child) && child.expression.getText(sf) === set && child.arguments[0]) setters.push(child.arguments[0]);
          if (ts.isIdentifier(child) && child.text === name) {
            references.push(child);
            if (parentList(child).some(p => ts.isJsxAttribute(p) && p.name.getText(sf) === 'value')) input = true;
          }
          ts.forEachChild(child, scan);
        }
        scan(sf);
        const authored = setters.some(argument => (ts.isStringLiteralLike(argument) && human(argument.text)) || ts.isTemplateExpression(argument) && human(argument.head.text + argument.templateSpans.map(span => span.literal.text).join(' ')));
        const display = references.some(reference => parentList(reference).some(ts.isJsxExpression));
        if (authored && display && !input) messageStates.set(name, { node, set, type, setters, references });
      }
    }
    if (ts.isFunctionDeclaration(node) || ts.isArrowFunction(node)) {
      const name = node.name?.text ?? (ts.isVariableDeclaration(node.parent) ? node.parent.name.getText(sf) : '');
      if (node.body && /set(?:Snackbar|Toast|Notice|Notification|Message)\(/.test(node.body.getText(sf))) {
        const parameters = node.parameters.map((parameter, index) => ({ parameter, index })).filter(({ parameter }) => /^(?:message|msg|text|notice|successMessage|successText)$/.test(parameter.name.getText(sf)) && parameter.type?.kind === ts.SyntaxKind.StringKeyword);
        if (parameters.length) notifier.set(name, parameters);
      }
    }
    ts.forEachChild(node, collect);
  }
  collect(sf);
  for (const state of messageStates.values()) {
    use('MessageText');
    if (state.type) edit(state.type, state.type.getText(sf).replace(/\bstring\b/g, 'MessageText'), 'display-only-state-message-type');
    else edits.push({ start: state.node.initializer.expression.end, end: state.node.initializer.expression.end, replacement: '<MessageText>', reason: 'display-only-state-message-type' });
    for (const argument of state.setters) { const next = make(argument, true); if (next !== argument.getText(sf)) edit(argument, next, 'deferred-display-state-source'); }
    for (const reference of state.references) {
      if (parentList(reference).some(parent => ts.isCallExpression(parent) && /^(?:i18nRenderText|renderText|messageSource)$/.test(parent.expression.getText(sf)))) continue;
      const p = reference.parent;
      if (ts.isJsxExpression(p) && p.expression === reference) edit(reference, `${use('renderText')}(${reference.text})`, 'reactive-display-state-binding');
    }
  }
  for (const parameters of notifier.values()) for (const { parameter } of parameters) { use('MessageText'); edit(parameter.type, 'MessageText', 'deferred-notifier-contract'); }
  function visit(node) {
    if (ranges.some(([start, end]) => node.getStart(sf) >= start && node.end <= end)) return;
    if (ts.isCallExpression(node)) {
      const parameters = notifier.get(node.expression.getText(sf));
      if (parameters) for (const { index } of parameters) if (node.arguments[index]) { const argument = node.arguments[index], next = make(argument, true); if (next !== argument.getText(sf)) edit(argument, next, 'deferred-notifier-message'); }
      if (/^set.*(?:Error|Failure)$/.test(node.expression.getText(sf)) && node.arguments[0]) {
        function retain(child) {
          if (ts.isPropertyAccessExpression(child) && child.name.text === 'message' && /^(?:e|err|error|failure)$/i.test(child.expression.getText(sf))) { edit(child, `${use('errorText')}(${child.expression.getText(sf)})`, 'retain-error-descriptor-in-conditional'); return; }
          ts.forEachChild(child, retain);
        }
        retain(node.arguments[0]);
      }
      if (/^(?:translate|i18nText|richText|i18nRichText)$/.test(node.expression.getText(sf))) return;
    }
    if (ts.isTemplateExpression(node) || ts.isStringLiteralLike(node)) {
      const chain = parentList(node);
      if (chain.some(p => ts.isCallExpression(p) && /^(?:JSON\.stringify|console\.|translate|i18nText|message|i18nMessage|richText|i18nRichText)/.test(p.expression.getText(sf)))) return;
      const tuple = chain.find(ts.isArrayLiteralExpression), variable = chain.find(ts.isVariableDeclaration);
      if (tuple && variable && /^(?:rows|fields|details|stats|metrics|properties|info)$/.test(variable.name.getText(sf)) && tuple.elements.length >= 2 && ts.isStringLiteralLike(tuple.elements[0])) {
        const index = tuple.elements.findIndex(element => node.getStart() >= element.getStart() && node.end <= element.end);
        if (index > 0) { const next = make(node); if (next !== node.getText(sf)) edit(node, next, 'authored-presentation-value-with-raw-evidence-parameters'); }
      }
    }
    if (ts.isJsxExpression(node) && node.expression) {
      const expression = node.expression;
      const attribute = ts.isJsxAttribute(node.parent) ? node.parent.name.getText(sf) : null;
      const display = attribute === null || /^(?:label|title|primary|secondary|aria-label|data-learn)$/.test(attribute);
      if (display && ts.isPropertyAccessExpression(expression)) {
        const raw = expression.getText(sf), owner = expression.expression.getText(sf), field = expression.name.text;
        if (['recordType', 'auditType'].includes(field) || field === 'type' && /^(?:file|auditFile|option|decoder|field|f|rule)$/.test(owner)) { edit(expression, `${use('recordTypeLabel')}(${raw})`, 'display-only-record-type-label'); return; }
        if (field === 'severity' || ['state', 'status', 'mode', 'scope'].includes(field) && /^(?:live|report|job|download|execution|health|validation|stats)$/.test(owner)) { edit(expression, `${use('enumLabel')}(${raw})`, 'display-only-enum-label'); return; }
        if (field === 'name' && /^(?:field|f|column)$/.test(owner) && /(?:Explore|Records|Audit|Decoders|ChartConfig|Protobuf)/.test(file.file)) { edit(expression, `${use('fieldLabel')}(${raw})`, 'schema-field-display-label'); return; }
        if (['label', 'description'].includes(field) && /^(?:action|example|typeInfo|ct|chartType)$/.test(owner)) { edit(expression, `${use('metadataText')}(${owner}, ${JSON.stringify(field)})`, 'authored-or-structured-metadata-label'); return; }
      }
      if (display && ts.isIdentifier(expression) && /^(?:header|fieldName|columnName)$/.test(expression.text)) { edit(expression, `${use('fieldLabel')}(${expression.text})`, 'schema-header-display-label'); return; }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  if (!edits.length) continue;
  if (used.size) {
    const existing = sf.statements.filter(ts.isImportDeclaration), start = existing.at(-1)?.end ?? sf.statements[0]?.getStart(sf) ?? 0;
    edits.push({ start, end: start, replacement: `\nimport { ${[...used].map(name => name === 'MessageText' ? 'type MessageText' : name).join(', ')} } from ${JSON.stringify(moduleFor(file))};\n`, reason: 'display-localization-imports' });
  }
  let output = text, boundary = text.length;
  for (const edit of edits.sort((a, b) => b.start - a.start)) { if (edit.end > boundary) throw new Error(`Overlapping display refinements: ${file.file}`); output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end); boundary = edit.start; }
  fs.writeFileSync(absolute, output); report.push({ file: file.file, edits: edits.map(({ start, reason }) => ({ line: sf.getLineAndCharacterOfPosition(start).line + 1, reason })) });
}
fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
fs.writeFileSync(path.join(frontend, 'localization/final-display-migration.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ files: report.length, messages: Object.keys(stage.messages).length }));
