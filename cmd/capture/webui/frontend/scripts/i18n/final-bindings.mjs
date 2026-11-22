import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { frontend, roots, parentOwned } from './config.mjs';
import { inventory } from './inventory.mjs';
const snapshot = inventory(), report = [];
for (const file of snapshot.files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json')) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8');
  const sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const edits = [], names = new Set(), ranges = [];
  const add = (node, replacement, reason) => { if (ranges.some(([a, b]) => node.getStart(sf) >= a && node.end <= b)) return; ranges.push([node.getStart(sf), node.end]); edits.push({ start: node.getStart(sf), end: node.end, replacement, reason }); };
  const ancestors = node => { const result = []; for (let p = node.parent; p; p = p.parent) result.push(p); return result; };
  function visit(node) {
    if (ranges.some(([a, b]) => node.getStart(sf) >= a && node.end <= b)) return;
    if (file.file.endsWith('/lib/timelineTime.ts') && ts.isFunctionDeclaration(node)) {
      const name = node.name?.text;
      if (name === 'formatClock') { names.add('formatClockNs'); add(node, `export function formatClock(ns: bigint, utc = false): string { try { return formatClockNs(ns, utc ? 'UTC' : Intl.DateTimeFormat().resolvedOptions().timeZone); } catch { return '—'; } }`, 'exact-localized-timeline-clock'); return; }
      if (name === 'formatDate') { names.add('formatCalendarDateNs'); add(node, `export function formatDate(ns: bigint, utc = false): string { try { return formatCalendarDateNs(ns, utc ? 'UTC' : Intl.DateTimeFormat().resolvedOptions().timeZone); } catch { return '—'; } }`, 'localized-timeline-calendar-date'); return; }
      if (name === 'formatSpan') { names.add('formatDurationNs'); add(node, `export function formatSpan(ns: bigint): string { return formatDurationNs(ns < 0n ? -ns : ns); }`, 'exact-nanosecond-timeline-span'); return; }
      if (name === 'formatOffset') { names.add('formatDurationNs'); add(node, `export function formatOffset(ns: bigint): string { return (ns < 0n ? '-' : '+') + formatDurationNs(ns < 0n ? -ns : ns); }`, 'exact-nanosecond-timeline-offset'); return; }
    }
    if (file.file.endsWith('/lib/chartConfig.ts') && ts.isFunctionDeclaration(node) && node.name?.text === 'getChartTypeLabel') {
      names.add('translate'); add(node, `export function getChartTypeLabel(value: string): string { const item = CHART_TYPES.find(c => c.value === value); return item ? translate(item.label) : value; }`, 'known-chart-type-label-only'); return;
    }
    if (file.file.endsWith('/components/ChartConfigDialog.tsx') && ts.isPropertyAccessExpression(node) && node.getText(sf) === 'c.label' && ancestors(node).some(ts.isJsxExpression)) { names.add('translate'); add(node, 'translate(c.label)', 'builtin-chart-type-label'); return; }
    if (file.file.endsWith('/components/ChartConfigDialog.tsx') && ts.isCallExpression(node) && node.expression.getText(sf) === 'recordTypeLabel' && node.arguments[0]?.getText(sf) === 'f.type') { names.add('metadataText'); add(node, `metadataText(f, 'type')`, 'structured-chart-field-type-label'); return; }
    if (ts.isCallExpression(node) && /^(?:i18nText|translate)$/.test(node.expression.getText(sf)) && node.arguments[0]?.getText(sf) === 'row.basis') { names.add('enumLabel'); add(node, 'enumLabel(row.basis)', 'explicit-evidence-basis-display-label'); return; }
    if (file.file.endsWith('/pages/ConfigPage.tsx') && ts.isJsxExpression(node) && node.expression?.getText(sf) === 'category' && !ts.isJsxAttribute(node.parent)) { names.add('metadataText'); add(node.expression, `metadataText(options[0], 'category', category)`, 'structured-category-label-with-canonical-group-key'); return; }
    if (ts.isCallExpression(node) && /^(?:useMemo|useCallback|useEffect)$/.test(node.expression.getText(sf)) && node.arguments[0] && node.arguments[1] && ts.isArrayLiteralExpression(node.arguments[1]) && !node.arguments[1].elements.some(element => element.getText(sf) === '__uiLocale')) {
      const body = node.arguments[0].getText(sf), parents = ancestors(node);
      const component = parents.find(parent => (ts.isFunctionDeclaration(parent) || ts.isFunctionExpression(parent)) && parent.body && parent.body.getText(sf).includes('const __uiLocale ='));
      const presentation = /i18nText\(|i18nRichText\(|translate\(|metadataText\(|format(?:Clock|Tick|Span|Date|Number|Timestamp)|getChartTypeLabel|\.fillText\(/.test(body);
      const mutation = /\b(?:api\.|fetch\(|mutate\(|set[A-Z][A-Za-z]*\(|navigate\(|localStorage\.)/.test(body.replace(/\.setTransform\(/g, '.transform('));
      if (component && presentation && !mutation) {
        const dependencies = node.arguments[1]; edits.push({ start: dependencies.end - 1, end: dependencies.end - 1, replacement: `${dependencies.elements.length ? ', ' : ''}__uiLocale`, reason: 'redraw-presentation-without-reinitializing-data-state' });
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  if (!edits.length) continue;
  const imports = sf.statements.filter(ts.isImportDeclaration), already = new Set(imports.flatMap(statement => statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings) ? statement.importClause.namedBindings.elements.map(item => item.name.text) : []));
  const required = [...names].filter(name => !already.has(name));
  if (required.length) {
    let module = file.repo === 'netcap-pro' ? path.posix.relative(path.posix.dirname(file.file), 'frontend/src/lib/i18n') : path.posix.relative(path.posix.dirname(file.file), 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n');
    if (!module.startsWith('.')) module = './' + module;
    const position = imports.at(-1)?.end ?? sf.statements[0]?.getStart(sf) ?? 0;
    edits.push({ start: position, end: position, replacement: `\nimport { ${required.join(', ')} } from ${JSON.stringify(module)};\n`, reason: 'display-binding-imports' });
  }
  let output = text, boundary = text.length;
  for (const edit of edits.sort((a, b) => b.start - a.start)) { if (edit.end > boundary) throw new Error(`Overlapping final bindings: ${file.file}`); output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end); boundary = edit.start; }
  fs.writeFileSync(absolute, output); report.push({ file: file.file, edits: edits.map(({ reason, start }) => ({ reason, line: sf.getLineAndCharacterOfPosition(start).line + 1 })) });
}
fs.writeFileSync(path.join(frontend, 'localization/display-bindings.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ files: report.length }));
