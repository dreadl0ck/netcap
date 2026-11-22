import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { frontend, roots, parentOwned, namespaceFor } from './config.mjs';
import { inventory, stableKey, escapeICU } from './inventory.mjs';

const stageFile = path.join(frontend, 'localization/full-staging.json');
const stage = JSON.parse(fs.readFileSync(stageFile, 'utf8'));
for (const id of ['removed:m_782d7e40bc485cc9f940', 'removed:m_58e072f9902ab4f9b525', 'removed:m_12b416942392091b6671']) delete stage.messages[id];
for (const entry of Object.values(stage.messages)) if (entry.locations.some(location => location.file === 'types/netcap.proto')) entry.context = 'Human-readable schema field/type display caption, NOT a wire identifier. Translate descriptive words naturally; preserve protocol acronyms. Captured data keys remain unchanged in the UI.';
const templates = {
  'AuditPage.tsx': ['Session: {arg0}'],
  'RecordsPage.tsx': ['Session: {arg0}'],
  'LogsPage.tsx': ['Session: {arg0}'],
  'BehaviorPage.tsx': ['Select {arg0}'],
  'DomainsPage.tsx': ['Code {arg0}'],
  'WiresharkButton.tsx': ['Error: {arg0}'],
  'timeline.tsx': ['{arg0}/{arg1} tracks'],
};
const report = [];
for (const file of inventory().files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json')) continue;
  const filename = path.basename(file.file), allowed = templates[filename] ?? [];
  if (!allowed.length && filename !== 'ProtobufPage.tsx') continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8');
  const sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const edits = [], imports = new Set();
  const replace = (node, replacement) => edits.push({ start: node.getStart(sf), end: node.end, replacement });
  function localized(node, deferred) {
    let source = ts.isTemplateExpression(node) ? node.head.text : node.text;
    const values = [];
    if (ts.isTemplateExpression(node)) node.templateSpans.forEach((span, index) => {
      source += `{arg${index}}${span.literal.text}`;
      const raw = span.expression.getText(sf);
      values.push(`arg${index}: ${/^(?:port|rc)$/.test(raw) ? `String(${raw})` : raw}`);
    });
    let pattern = ts.isTemplateExpression(node) ? escapeICU(node.head.text) : escapeICU(source);
    if (ts.isTemplateExpression(node)) node.templateSpans.forEach((span, index) => { pattern += `{arg${index}}${escapeICU(span.literal.text)}`; });
    if (source === '{arg0}/{arg1} tracks') pattern = '{arg0, number}/{arg1, plural, one {# track} other {# tracks}}';
    if (source === 'Uploaded {arg0} file(s)') pattern = '{arg0, plural, one {Uploaded # file} other {Uploaded # files}}';
    const namespace = namespaceFor(file.file, source), key = stableKey(pattern), id = `${namespace}:${key}`;
    stage.messages[id] ??= { namespace, key, message: pattern, context: 'Reviewed application-authored display copy; interpolation values remain raw.', locations: [{ repo: file.repo, file: file.file, line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1, source }] };
    imports.add(deferred ? 'message as i18nMessage' : 'translate as i18nText');
    return `${deferred ? 'i18nMessage' : 'i18nText'}(${JSON.stringify(id)}${values.length ? ', { ' + values.join(', ') + ' }' : ''})`;
  }
  function visit(node) {
    if (filename === 'RecordsPage.tsx' && ts.isStringLiteral(node) && node.text === 'N/A') { replace(node, localized(node, false)); return; }
    if (ts.isCallExpression(node) && /^(?:showSuccess|showError)$/.test(node.expression.getText(sf)) && filename === 'ProtobufPage.tsx') {
      const arg = node.arguments[0];
      if (arg && (ts.isStringLiteralLike(arg) || ts.isTemplateExpression(arg))) { replace(arg, localized(arg, true)); return; }
    }
    if (ts.isTemplateExpression(node)) {
      const source = node.head.text + node.templateSpans.map((span, index) => `{arg${index}}${span.literal.text}`).join('');
      if (allowed.includes(source)) { replace(node, localized(node, false)); return; }
    }
    if (filename === 'DomainsPage.tsx' && ts.isStringLiteral(node) && ['Success', 'Refused'].includes(node.text) && ts.isConditionalExpression(node.parent)) { replace(node, localized(node, false)); return; }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  if (!edits.length) continue;
  const declarations = sf.statements.filter(ts.isImportDeclaration), bound = new Set(declarations.flatMap(statement => statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings) ? statement.importClause.namedBindings.elements.map(item => item.name.text) : []));
  const names = [...imports].filter(name => !bound.has(name.split(' as ').at(-1)));
  if (names.length) {
    let module = path.posix.relative(path.posix.dirname(file.file), file.repo === 'netcap-pro' ? 'frontend/src/lib/i18n' : 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n');
    if (!module.startsWith('.')) module = './' + module;
    const position = declarations.at(-1)?.end ?? 0;
    edits.push({ start: position, end: position, replacement: `\nimport { ${names.join(', ')} } from ${JSON.stringify(module)};\n` });
  }
  let output = text, boundary = text.length;
  for (const edit of edits.sort((a, b) => b.start - a.start)) {
    if (edit.end > boundary) throw new Error(`Overlapping reviewed edit: ${file.file}`);
    output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end); boundary = edit.start;
  }
  fs.writeFileSync(absolute, output); report.push({ repo: file.repo, file: file.file, edits: edits.length });
}
for (const [namespace, key, message, file] of [
  ['removed', 'machine.genericName', 'Machine', 'pages/graph.tsx'],
  ...Object.entries({ userReport: 'User report', endpointResult: 'Endpoint result', proxyNatLog: 'Proxy/NAT log', routingSnapshot: 'Routing/interface snapshot', debuggerStack: 'Debugger stack', other: 'Other' }).map(([key, text]) => ['ui', `artifact.kind.${key}`, text, 'lib/i18n/labels.ts']),
  ...Object.entries({ approve: 'Approve', pause: 'Pause', resume: 'Resume', relearn: 'Relearn', reset: 'Reset', acknowledge: 'Acknowledge', 'approve-changes': 'Approve changes', suppress: 'Suppress', unsuppress: 'Unsuppress' }).map(([key, text]) => ['ui', `behavior.action.${key}`, text, 'lib/i18n/labels.ts']),
  ...Object.entries({ learning: 'Learning', monitoring: 'Monitoring', paused: 'Paused' }).map(([key, text]) => ['ui', `status.${key}`, text, 'lib/i18n/labels.ts']),
  ['direct', 'updater.progress', 'Downloading {done, number, ::.0}/{total, number, ::.0} MiB', 'components/UpdateBanner.tsx'],
  ['ui', 'dns.transactions.unanswered', '{count, number} unanswered', 'lib/dnsTransactions.ts'],
  ['ui', 'dns.transactions.unsolicited', '{count, number} unsolicited', 'lib/dnsTransactions.ts'],
  ['ui', 'dns.transactions.retransmitted', '{count, number} retransmitted', 'lib/dnsTransactions.ts'],
  ['ui', 'dns.transactions.late', '{count, number} late', 'lib/dnsTransactions.ts'],
  ['ui', 'dns.transactions.reordered', '{count, number} clock-order unknown', 'lib/dnsTransactions.ts'],
  ['ui', 'dns.transactions.truncated', 'RTT sample limit reached', 'lib/dnsTransactions.ts'],
  ['ui', 'protobuf.defaultPackage', '(default)', 'pages/ProtobufPage.tsx'],
  ['ui', 'selection.allPackets', 'all packets in window', 'pages/PcapsPage.tsx'],
  ['ui', 'bpf.saveFailed', 'Failed to save BPF filter', 'pages/BPFPage.tsx'],
  ['ui', 'protobuf.uploaded', '{count, plural, one {Uploaded # file} other {Uploaded # files}}', 'pages/ProtobufPage.tsx'],
  ['ui', 'protobuf.alternatives', '{enabled, select, true {Show alternatives: on} other {Show alternatives: off}}', 'pages/ProtobufPage.tsx'],
  ['removed', 'similarity.packetsPerSecond', '{count, plural, one {# packet/s} other {# packets/s}}', 'lib/similarity.ts'],
  ['removed', 'graph.machine.truncated', '(kept the highest-risk {kept}; {count, plural, one {# more via individual transforms} other {# more via individual transforms}})', 'pages/graph.tsx'],
]) stage.messages[`${namespace}:${key}`] = { namespace, key, message, context: 'Reviewed display formatting with raw evidence/identifier values retained.', locations: [{ repo: namespace === 'ui' ? 'netcap' : 'netcap-pro', file: namespace === 'ui' ? `cmd/capture/webui/frontend/packages/netcap-ui/src/${file}` : `frontend/src/${file}`, line: 1, source: message }] };
fs.writeFileSync(stageFile, JSON.stringify(stage, null, 2) + '\n');
fs.writeFileSync(path.join(frontend, 'localization/finish-reviewed-migration.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ files: report.length, messages: Object.keys(stage.messages).length }));
