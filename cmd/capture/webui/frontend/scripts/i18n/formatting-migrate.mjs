import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { frontend, roots, parentOwned } from './config.mjs';
import { inventory } from './inventory.mjs';
const snapshot = inventory(), changed = [];
for (const file of snapshot.files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json') || /\/(?:Preferences|PresentationControls|AppearanceControls)/.test(file.file)) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8');
  const sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const edits = [], names = new Set();
  const add = (node, replacement, reason) => edits.push({ start: node.getStart(sf), end: node.end, replacement, reason });
  const ancestry = node => { const result = []; for (let p = node.parent; p; p = p.parent) result.push(p); return result; };
  function visit(node) {
    if (ts.isFunctionDeclaration(node) && file.file.endsWith('/src/lib/api.ts')) {
      if (node.name?.text === 'formatBytes') {
        names.add('formatNumber'); names.add('formatBytes as formatExactBytes');
        add(node, `export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes)) return '—';
  if (Number.isSafeInteger(bytes)) return formatExactBytes(BigInt(bytes));
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'];
  const exponent = bytes === 0 ? 0 : Math.min(units.length - 1, Math.max(0, Math.floor(Math.log(Math.abs(bytes)) / Math.log(1024))));
  return formatNumber(bytes / 1024 ** exponent, { maximumFractionDigits: 2 }) + '\u00a0' + units[exponent];
}`, 'explicit-iec-byte-format'); return;
      }
      if (node.name?.text === 'formatTimestamp') {
        names.add('formatTimestampNs'); names.add('formatDateTime');
        add(node, `export function formatTimestamp(timestamp: number | string | bigint, unit: 'seconds' | 'milliseconds' | 'nanoseconds'): string {
  if (timestamp === 0 || timestamp === 0n || timestamp === '0' || timestamp === '') return '—';
  try {
    if (unit === 'nanoseconds' && typeof timestamp !== 'number') return formatTimestampNs(timestamp);
    if (unit === 'nanoseconds' && Number.isSafeInteger(timestamp)) return formatTimestampNs(BigInt(timestamp));
    // Legacy JSON numbers may already be rounded; do not invent a nine-digit fraction.
    const value = Number(timestamp);
    return formatDateTime(unit === 'nanoseconds' ? value / 1e6 : value, unit === 'seconds' ? 'seconds' : 'milliseconds');
  } catch { return '—'; }
}`, 'explicit-timestamp-unit-no-magnitude-guess'); return;
      }
      if (node.name?.text === 'formatDuration') {
        names.add('formatQuantity');
        add(node, `export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) return '—';
  const value = Math.abs(seconds);
  return value < 1 ? formatQuantity(seconds * 1000, 'ms') : value < 60 ? formatQuantity(seconds, 's') : value < 3600 ? formatQuantity(seconds / 60, 'min') : value < 86400 ? formatQuantity(seconds / 3600, 'h') : formatQuantity(seconds / 86400, 'd');
}`, 'explicit-seconds-duration'); return;
      }
    }
    if (ts.isCallExpression(node) && node.expression.getText(sf) === 'formatTimestamp' && node.arguments.length === 1) {
      const value = node.arguments[0].getText(sf), unit = /\.(?:modifiedTime|uploadTimestamp|mtime)$/.test(value) ? 'seconds' : 'nanoseconds';
      edits.push({ start: node.arguments[0].end, end: node.arguments[0].end, replacement: `, '${unit}'`, reason: unit === 'seconds' ? 'file-mtime-unix-seconds-verified-in-go' : 'audit-and-alert-unix-nanoseconds-verified-in-go' });
    }
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const method = node.expression.name.text;
      const program = ancestry(node).some(parent => ts.isTaggedTemplateExpression(parent) || ts.isPropertyAssignment(parent) && ['sx', 'style', 'vertexShader', 'fragmentShader'].includes(parent.name.getText(sf))) || /(?:SyntaxHighlight|\/html\.ts|\/replay\.ts|\/graphLayout\.ts|appearance|theme\.ts)/.test(file.file);
      if (!program && ['toLocaleString', 'toLocaleDateString', 'toLocaleTimeString'].includes(method) && node.arguments.length === 0) {
        names.add('getLocale'); add(node, `${node.expression.getText(sf)}(getLocale())`, 'explicit-active-locale'); return;
      }
      if (!program && method === 'toFixed') {
        const parents = ancestry(node);
        const numericRounding = ts.isCallExpression(node.parent) && /^(?:Number|parseFloat|parseInt)$/.test(node.parent.expression.getText(sf));
        const fn = parents.find(parent => ts.isFunctionDeclaration(parent) || ts.isArrowFunction(parent));
        const name = fn?.name?.text ?? (fn?.parent && ts.isVariableDeclaration(fn.parent) ? fn.parent.name.getText(sf) : '');
        if (!numericRounding && (parents.some(ts.isJsxExpression) || /format|label|clock|tick|span|size/i.test(name) || /\/(?:similarity|timelineTime)\.ts$/.test(file.file))) {
          names.add('formatNumber'); const digits = node.arguments[0]?.getText(sf) ?? '0';
          add(node, `formatNumber(${node.expression.expression.getText(sf)}, { minimumFractionDigits: ${digits}, maximumFractionDigits: ${digits}, useGrouping: false })`, 'localized-display-decimal'); return;
        }
      }
    }
    // Exact IDs and timestamps remain canonical interpolation values.
    if (ts.isPropertyAssignment(node) && /^arg\d+$/.test(node.name.getText(sf)) && ts.isPropertyAccessExpression(node.initializer) && /^(?:id|ordinal|port|srcPort|dstPort|timestampNs|startNs|endNs|schema|sequence|version)$/.test(node.initializer.name.text)) {
      add(node.initializer, `String(${node.initializer.getText(sf)})`, 'preserve-canonical-identifier-and-nanosecond-digits'); return;
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  if (!edits.length) continue;
  const existing = sf.statements.filter(ts.isImportDeclaration), already = new Set(existing.flatMap(statement => statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings) ? statement.importClause.namedBindings.elements.map(item => item.name.text) : []));
  const imported = [...names].filter(name => !already.has(name.includes(' as ') ? name.split(' as ')[1] : name));
  if (imported.length) {
    let module = file.repo === 'netcap-pro' ? path.posix.relative(path.posix.dirname(file.file), 'frontend/src/lib/i18n') : path.posix.relative(path.posix.dirname(file.file), 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n');
    if (!module.startsWith('.')) module = './' + module;
    const start = existing.at(-1)?.end ?? sf.statements[0]?.getStart(sf) ?? 0;
    edits.push({ start, end: start, replacement: `\nimport { ${imported.join(', ')} } from ${JSON.stringify(module)};\n`, reason: 'formatting-imports' });
  }
  let output = text, boundary = text.length;
  for (const edit of edits.sort((a, b) => b.start - a.start)) {
    if (edit.end > boundary) throw new Error(`Overlapping formatting changes: ${file.file}`);
    output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end); boundary = edit.start;
  }
  fs.writeFileSync(absolute, output); changed.push({ file: file.file, edits: edits.map(({ reason, start }) => ({ reason, line: sf.getLineAndCharacterOfPosition(start).line + 1 })) });
}
fs.writeFileSync(path.join(frontend, 'localization/formatting-migration.json'), JSON.stringify(changed, null, 2) + '\n');
console.log(JSON.stringify({ files: changed.length, edits: changed.reduce((sum, file) => sum + file.edits.length, 0) }));
