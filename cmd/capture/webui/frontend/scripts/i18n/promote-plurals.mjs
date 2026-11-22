import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { frontend, roots, parentOwned } from './config.mjs';
import { inventory } from './inventory.mjs';
const snapshot = inventory(), stagePath = path.join(frontend, 'localization/full-staging.json'), stage = JSON.parse(fs.readFileSync(stagePath, 'utf8'));
const temporary = process.env.NETCAP_I18N_DEPS_ROOT;
const options = { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, moduleResolution: ts.ModuleResolutionKind.Bundler, jsx: ts.JsxEmit.ReactJSX, strict: true, skipLibCheck: true, resolveJsonModule: true, esModuleInterop: true, baseUrl: frontend,
  paths: { '@dreadl0ck/netcap-ui/i18n': [path.join(frontend, 'packages/netcap-ui/src/lib/i18n.ts')], ...(temporary ? Object.fromEntries(['i18next', 'i18next-icu', 'react-i18next', 'intl-messageformat'].map(name => [name, [path.join(temporary, 'node_modules', name)]])) : {}) } };
const program = ts.createProgram(snapshot.files.filter(file => !file.html && !file.file.endsWith('.json')).map(file => path.join(roots[file.repo], file.file)), options), checker = program.getTypeChecker();
const callers = new Map();
for (const file of snapshot.files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json')) continue;
  const absolute = path.join(roots[file.repo], file.file), sf = program.getSourceFile(absolute);
  if (!sf) continue;
  function visit(node) {
    if (ts.isCallExpression(node) && /^(?:translate|message|richText|i18nText|i18nMessage|i18nRichText)$/.test(node.expression.getText(sf)) && node.arguments[0] && ts.isStringLiteral(node.arguments[0])) {
      const id = node.arguments[0].text;
      if (stage.messages[id] && node.arguments[1] && ts.isObjectLiteralExpression(node.arguments[1])) {
        const arguments_ = new Map(node.arguments[1].properties.filter(ts.isPropertyAssignment).map(property => [property.name.getText(sf), property.initializer]));
        callers.set(id, [...(callers.get(id) ?? []), { file, sf, arguments: arguments_ }]);
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
}
const forms = { packets: 'packet', records: 'record', files: 'file', alerts: 'alert', connections: 'connection', hosts: 'host', devices: 'device', services: 'service', domains: 'domain', fingerprints: 'fingerprint', queries: 'query', clients: 'client', occurrences: 'occurrence', results: 'result', flows: 'flow', observations: 'observation', rules: 'rule', events: 'event', rows: 'row', items: 'item', matches: 'match', groups: 'group', captures: 'capture', days: 'day', hours: 'hour', minutes: 'minute', seconds: 'second', bytes: 'byte', errors: 'error', steps: 'step', transforms: 'transform', nodes: 'node', edges: 'edge', ports: 'port' };
const noun = new RegExp(`\\{([A-Za-z][A-Za-z0-9_]*)\\}(\\s+(?:(?:total|unique|enabled|disabled|selected|retained|analyzed|remaining)\\s+)?)(` + Object.keys(forms).join('|') + ')\\b', 'g');
const edits = new Map(), promoted = [];
for (const [id, entry] of Object.entries(stage.messages)) {
  if (/,\s*(?:plural|select|selectordinal)\s*,/.test(entry.message)) continue;
  const matches = [...entry.message.matchAll(noun)];
  if (!matches.length) continue;
  const calls = callers.get(id) ?? [];
  const eligible = new Map();
  for (const match of matches) {
    const name = match[1];
    const expressions = calls.map(call => call.arguments.get(name));
    const numeric = expressions.length > 0 && expressions.every(expression => {
      if (!expression) return false;
      const value = ts.isCallExpression(expression) && ts.isPropertyAccessExpression(expression.expression) && expression.expression.name.text === 'toLocaleString' ? expression.expression.expression : expression;
      const type = checker.getTypeAtLocation(value);
      return Boolean(type.flags & (ts.TypeFlags.NumberLike | ts.TypeFlags.BigIntLike)) || ts.isPropertyAccessExpression(value) && value.name.text === 'length';
    });
    if (numeric) eligible.set(name, matches.filter(candidate => candidate[1] === name));
  }
  if (!eligible.size) continue;
  let pattern = entry.message.replaceAll('#', "'#'");
  for (const [name, occurrences] of eligible) {
    const one = pattern.replace(noun, (whole, variable, spacing, plural) => variable === name ? `{${name}}${spacing}${forms[plural]}` : whole).replaceAll(`{${name}}`, `{${name}, number}`);
    const other = pattern.replaceAll(`{${name}}`, `{${name}, number}`);
    pattern = `{${name}, plural, one {${one}} other {${other}}}`;
    for (const call of calls) {
      const expression = call.arguments.get(name);
      if (expression && ts.isCallExpression(expression) && ts.isPropertyAccessExpression(expression.expression) && expression.expression.name.text === 'toLocaleString') {
        const file = path.join(roots[call.file.repo], call.file.file);
        edits.set(file, [...(edits.get(file) ?? []), { start: expression.getStart(call.sf), end: expression.end, replacement: expression.expression.expression.getText(call.sf) }]);
      }
    }
  }
  promoted.push({ id, before: entry.message, after: pattern }); entry.message = pattern;
}
for (const [file, changes] of edits) {
  const unique = [...new Map(changes.map(change => [change.start, change])).values()].sort((a, b) => b.start - a.start);
  let source = fs.readFileSync(file, 'utf8');
  for (const edit of unique) source = source.slice(0, edit.start) + edit.replacement + source.slice(edit.end);
  fs.writeFileSync(file, source);
}
fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
fs.writeFileSync(path.join(frontend, 'localization/plural-migration.json'), JSON.stringify(promoted, null, 2) + '\n');
console.log(JSON.stringify({ promotedICUMessages: promoted.length, numericBindings: [...edits.values()].reduce((sum, file) => sum + file.length, 0) }));
