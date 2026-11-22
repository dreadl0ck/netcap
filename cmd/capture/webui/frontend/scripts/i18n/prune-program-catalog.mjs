import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { frontend, roots, parentOwned } from './config.mjs';
import { inventory } from './inventory.mjs';
const stagePath = path.join(frontend, 'localization/full-staging.json'), stage = JSON.parse(fs.readFileSync(stagePath, 'utf8'));
const placements = new Set(['workspace-before-pcaps', 'data-before-logs', 'detection-end', 'system-start', 'system-before-bpf']);
function program(entry) {
  const source = entry.locations[0]?.source ?? entry.message, text = source.trim();
  if (/^(?:rgba?|hsla?|linear-gradient|radial-gradient|var|calc)\(/.test(text)) return 'CSS value, not UI copy';
  if (/^\.(?:json-|Mui)|^\s*(?:@media|[.#][A-Za-z_-]+\s*\{)/.test(source)) return 'CSS stylesheet program, not UI copy';
  if (/^(?:\/[^\s]*|https?:\/\/[^\s]+|[A-Za-z]:\\)/.test(text)) return 'Canonical URL/route/path; never translate';
  if (placements.has(text)) return 'Navigation placement enum; never translate';
  if (/^(?:[A-Za-z_][A-Za-z0-9_.]*(?:\[[0-9]+\])?(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*(?:==|!=|>=|<=|<|>|=~|!~)\s*/.test(text)) return 'Filter expression with canonical field IDs/operators';
  if (/^(?:IsPrivateIP|IsPublicIP|InSubnet|ParsePort|PortInRange|TimeInRange|Contains|Has|Len|Count|Sum|Avg|Min|Max)\(/.test(text)) return 'Filter function expression; preserve executable syntax';
  if (/^[A-Za-z_][A-Za-z0-9_.]*\(.*\)$/.test(text)) return 'Reviewed complete function-call example; preserve executable syntax';
  if (/^(?:tcp|udp|icmp|ip|ip6|ether|host|port|src|dst|net)(?:\s+(?:and|or|not|src|dst|host|port|net|tcp|udp|[0-9a-fA-F:./]+))+$/i.test(text)) return 'BPF filter syntax';
  if (/^(?:net (?:try|capture|util) -|SYN && !ACK && DstPort <|button, a, \[role=|M \d+,\d+ [LC]|DurationSince\(|\(DstPort ==)/.test(text) || /^\{arg0\}\{arg1\} capture -iface /.test(text)) return 'CLI/filter/selector/SVG program; preserve executable syntax';
  if (/^(?:trial_expired|license_expired|same-connection|same-flow|dns-resolution|resolved-connection)$/.test(text)) return 'Reviewed wire/status discriminant, never display prose';
  if (/^(?:card-\{arg\d+\}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)|^[\w.-]+\.(?:mmdb|bleve|sqlite|json)$/.test(text)) return 'Canonical artifact/DOM identifier or ISO timestamp example';
  if (['hosts', 'services'].includes(text) && entry.locations.every(item => /\/pages\/DbsPage\.tsx$/.test(item.file))) return 'Operating-system database filename/key; preserve canonical filename';
  if (['package.MessageName', 'proxy-nat-log', 'debugger-stack'].includes(text)) return 'Reviewed schema/artifact-kind identifier example; preserve canonical syntax';
  return null;
}
const removed = new Map();
for (const [id, entry] of Object.entries(stage.messages)) { const reason = program(entry); if (reason) removed.set(id, { entry, reason }); }
const snapshot = inventory(); let files = 0;
for (const file of snapshot.files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json')) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8'), sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const edits = []; let raw = false;
  function visit(node) {
    if (ts.isCallExpression(node) && /^(?:translate|i18nText|richText|i18nRichText|finalCopyText|i18nParameterText)$/.test(node.expression.getText(sf)) && node.arguments[0] && ts.isStringLiteral(node.arguments[0]) && removed.has(node.arguments[0].text)) {
      const { entry } = removed.get(node.arguments[0].text); raw = true;
      edits.push({ start: node.getStart(sf), end: node.end, replacement: `rawCode(${JSON.stringify(entry.message)}${node.arguments[1] ? ', ' + node.arguments[1].getText(sf) : ''})` }); return;
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  if (!edits.length) continue;
  const imports = sf.statements.filter(ts.isImportDeclaration), bound = imports.some(statement => statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings) && statement.importClause.namedBindings.elements.some(item => item.name.text === 'rawCode'));
  if (raw && !bound) {
    let module = path.posix.relative(path.posix.dirname(file.file), file.repo === 'netcap-pro' ? 'frontend/src/lib/i18n' : 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n'); if (!module.startsWith('.')) module = './' + module;
    const position = imports.at(-1)?.end ?? sf.statements[0]?.getStart(sf) ?? 0;
    edits.push({ start: position, end: position, replacement: `\nimport { rawCode } from ${JSON.stringify(module)};\n` });
  }
  let output = text;
  for (const edit of edits.sort((a, b) => b.start - a.start)) output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end);
  fs.writeFileSync(absolute, output); files++;
}
for (const id of removed.keys()) delete stage.messages[id];
const parentPath = path.join(frontend, 'localization/parent-messages.json'), parent = JSON.parse(fs.readFileSync(parentPath, 'utf8'));
fs.writeFileSync(parentPath, JSON.stringify(parent.filter(item => !removed.has(item.key)), null, 2) + '\n');
fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
const reportFile = path.join(frontend, 'localization/program-classification.json');
const previous = fs.existsSync(reportFile) ? JSON.parse(fs.readFileSync(reportFile, 'utf8')) : [];
fs.writeFileSync(reportFile, JSON.stringify([...previous.filter(item => !removed.has(item.id)), ...[...removed].map(([id, { entry, reason }]) => ({ id, source: entry.locations[0]?.source ?? entry.message, reason, locations: entry.locations }))], null, 2) + '\n');
console.log(JSON.stringify({ canonicalProgramsRemovedFromCatalog: removed.size, sourceFilesRestoredToRawCode: files }));
