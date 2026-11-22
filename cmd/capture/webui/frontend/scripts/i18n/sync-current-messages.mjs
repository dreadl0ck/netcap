import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { frontend, netcap, pro, roots, productionRoots, parentOwned, namespaceFor } from './config.mjs';
import { stableKey, escapeICU } from './inventory.mjs';
import { signature } from './schema.mjs';

export const preferenceSources = {
  appearance: 'Appearance', lightMode: 'Switch to light mode', darkMode: 'Switch to dark mode', language: 'Language', systemLanguage: 'System language',
  saveFailed: 'Could not save preferences.', sessionOnly: 'Preferences could not be saved. Your selection applies to this session.', light: 'Light', dark: 'Dark',
};
export const licenseSources = {
  activation: 'The license could not be activated.', restore: 'The saved license could not be restored.', network: 'Could not reach the license server.',
  ended: 'This license entitlement has ended.', trialExpired: 'The trial period has ended on this device.', expired: 'This license has expired.',
  validation: 'The license could not be validated.', device: 'This license belongs to another device.', product: 'This license belongs to another product.', storage: 'The license could not be saved on this device.',
};
export function sourceCalls(text, filename = 'source.tsx') {
  const source = ts.createSourceFile(filename, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX), found = new Map();
  function visit(node) {
    if (ts.isCallExpression(node) && /^(?:t|translate|message|richText|i18nText|i18nMessage|i18nRichText)$/.test(node.expression.getText(source)) && node.arguments[0] && ts.isStringLiteralLike(node.arguments[0])) found.set(node.arguments[0].text, source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1);
    ts.forEachChild(node, visit);
  }
  visit(source); return found;
}
export function syncCurrentMessages() {
  const directory = path.join(frontend, 'localization'), stageFile = path.join(directory, 'full-staging.json'), stage = JSON.parse(fs.readFileSync(stageFile, 'utf8'));
  const coverage = { captureChooser: {}, connections: {}, preferences: {}, licensing: {}, host: {} };
  function add(source, repo, file, line, key, namespace = 'ui') {
    signature(source);
    const existing = Object.entries(stage.messages).find(([, entry]) => entry.namespace === namespace && entry.message === source);
    const id = key ? `${namespace}:${key}` : existing?.[0] ?? `${namespace}:${stableKey(source)}`;
    stage.messages[id] ??= { namespace, key: id.slice(namespace.length + 1), message: source, context: 'Current capture/host presentation copy. Counts use ICU and captured parameters remain raw.', locations: [{ repo, file, line, source }] };
    return id;
  }
  const chooserFile = 'frontend/src/components/OpenCaptureButton.tsx';
  const chooser = sourceCalls(fs.readFileSync(path.join(pro, chooserFile), 'utf8'), chooserFile);
  for (const [source, line] of chooser) coverage.captureChooser[source] = add(source, 'netcap-pro', chooserFile, line);
  for (const [repo, file] of [['netcap', 'cmd/capture/webui/frontend/src/main.tsx'], ['netcap-pro', 'frontend/src/main.tsx']]) {
    const text = fs.readFileSync(path.join(roots[repo], file), 'utf8'), source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    function visit(node) {
      if (ts.isStringLiteralLike(node) && /^(?:Connecting to |Connection lost\.)/.test(node.text)) coverage.connections[node.text] = add(node.text, repo, file, source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1);
      ts.forEachChild(node, visit);
    }
    visit(source);
  }
  for (const [key, source] of Object.entries(preferenceSources)) coverage.preferences[source] = add(source, 'netcap', 'cmd/capture/webui/frontend/packages/netcap-ui/src/components/Layout.tsx', 1, `presentation.${key}`);
  for (const [key, source] of Object.entries(licenseSources)) coverage.licensing[source] = add(source, 'netcap-pro', 'frontend/src/lib/licensePresentation.ts', 1, `license.error.${key}`, 'direct');
  const logicalKeys = new Set();
  for (const namespace of ['ui', 'direct', 'removed']) for (const key of Object.keys(JSON.parse(fs.readFileSync(path.join(frontend, 'packages/netcap-ui/src/lib/i18n/catalogs', namespace, 'en.json'), 'utf8')))) { logicalKeys.add(`${namespace}:${key}`); if (namespace === 'ui') logicalKeys.add(key); }
  const missingLogicalKeys = [];
  function protectedSources(repo, directory) {
    if (!fs.existsSync(directory)) return;
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (['i18n', 'bindings', '__tests__'].includes(entry.name)) continue;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) { protectedSources(repo, absolute); continue; }
      const file = path.relative(roots[repo], absolute).split(path.sep).join('/');
      if (!parentOwned(file) || !/\.[jt]sx?$/.test(file) || /\.(?:test|spec|d)\.[jt]sx?$/.test(file)) continue;
      for (const [source, line] of sourceCalls(fs.readFileSync(absolute, 'utf8'), file)) {
        const existing = stage.messages[source] ? source : stage.messages[`ui:${source}`] ? `ui:${source}` : logicalKeys.has(source) ? source : undefined;
        if (existing) { coverage.host[source] = existing; continue; }
        if (/^(?:ui|direct|removed):|^[a-z][\w-]*(?:\.[\w-]+)+$/.test(source)) { missingLogicalKeys.push({ repo, file, line, source }); continue; }
        coverage.host[source] = add(source, repo, file, line, undefined, namespaceFor(file, source));
      }
    }
  }
  for (const root of productionRoots) protectedSources(root.repo, root.directory);
  const aliasesFile = path.join(frontend, 'packages/netcap-ui/src/lib/i18n/backend-ids.json'), aliases = JSON.parse(fs.readFileSync(aliasesFile, 'utf8'));
  const rows = JSON.parse(execFileSync('go', ['run', path.join(frontend, 'scripts/i18n/extract-metadata.go'), netcap, '--backend-ids'], { cwd: fileURLToPath(new URL('./', import.meta.url)), env: { ...process.env, GOTOOLCHAIN: 'local', GO111MODULE: 'off', GOWORK: 'off' }, encoding: 'utf8', maxBuffer: 2 * 1024 * 1024 }));
  const bySource = new Map();
  for (const [id, entry] of Object.entries(stage.messages)) {
    if (!bySource.has(entry.message) || entry.namespace === 'ui') bySource.set(entry.message, id);
    for (const location of entry.locations) if (location.source && (!bySource.has(location.source) || entry.namespace === 'ui')) bySource.set(location.source, id);
  }
  const unmapped = [];
  for (const row of rows.sort((a, b) => a.id.localeCompare(b.id) || a.source.localeCompare(b.source))) {
    const id = bySource.get(row.source) ?? bySource.get(escapeICU(row.source));
    if (id) aliases[row.id] = id;
    else unmapped.push({ id: row.id, source: row.source, file: row.file, line: row.line });
  }
  for (const [id, source] of Object.entries({ 'decoder.type.packet': 'Packet decoder', 'decoder.type.gopacket': 'Packet decoder (gopacket)', 'decoder.type.stream': 'Stream decoder', 'decoder.type.abstract': 'Abstract decoder', 'feature.scope.query': 'Next API request', 'feature.scope.capture': 'Next capture analysis', 'ruleset.enabled': 'Rule set {name} enabled ({count} rules affected)', 'ruleset.disabled': 'Rule set {name} disabled ({count} rules affected)', 'injection.rule.enabled': 'Injection rule enabled', 'injection.rule.disabled': 'Injection rule disabled' })) {
    const key = bySource.get(source); if (key) aliases[id] = key;
  }
  fs.writeFileSync(aliasesFile, JSON.stringify(aliases, null, 2) + '\n');
  fs.writeFileSync(stageFile, JSON.stringify(stage, null, 2) + '\n');
  const integrationFile = path.join(directory, 'integration.json'), integration = JSON.parse(fs.readFileSync(integrationFile, 'utf8'));
  integration.currentSourceCoverage = coverage;
  fs.writeFileSync(integrationFile, JSON.stringify(integration, null, 2) + '\n');
  console.log(JSON.stringify({ captureSources: chooser.size, connectionSources: Object.keys(coverage.connections).length, preferences: coverage.preferences, sharedBackendIDs: rows.length, unmappedBackendIDs: unmapped, missingHostLogicalKeys: missingLogicalKeys }, null, 2));
  return coverage;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) syncCurrentMessages();
