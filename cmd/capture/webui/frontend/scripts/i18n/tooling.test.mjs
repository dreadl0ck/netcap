import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSource, stableKey, digest, jsxText } from './inventory.mjs';
import { planFile } from './migrate.mjs';
import { extract } from './extract.mjs';
import { validateTranslation, validateCatalogObject, signature } from './schema.mjs';
import { translateBatch, validateBatch } from './translate.mjs';
import { prepareCatalogs } from './publish.mjs';
import { completionFindings } from './check.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { frontend, pro, locales, catalogsRoot } from './config.mjs';
import { sourceCalls, preferenceSources } from './sync-current-messages.mjs';
import { releaseEntries } from './sync-release-highlights.mjs';

test('AST inventories display sinks, metadata, callbacks, constants, interpolation and formatting without translating wire IDs', () => {
  const result = scanSource([
    "import X from 'a-package';",
    "const views = [{id: 'capture', field: 'SrcIP', question: 'Who talks to whom?', label: 'Hosts'}];",
    "const sentence = 'This helper text needs review';",
    'function Panel() {',
    "  const [error, setError] = useState('');",
    "  if (state === 'pending') setError('Could not open capture');",
    "  console.error('Internal diagnostic');",
    '  return <X aria-label="Open details" data-learn="Inspect a host" value="capture">',
    '    <button>Close</button><p>Showing {count} records</p><span>{count.toLocaleString()}</span><code>TCP</code>',
    '    <span>{`Found ${count} packets`}</span>',
    '  </X>;',
    '}',
  ].join('\n'));
  const get = value => result.occurrences.find(occurrence => occurrence.source === value);
  assert.equal(get('a-package').classification, 'canonical');
  assert.equal(get('SrcIP').classification, 'canonical');
  assert.equal(get('pending').classification, 'canonical');
  assert.equal(get('Internal diagnostic').classification, 'canonical');
  assert.equal(get('TCP').classification, 'canonical');
  assert.equal(get('Who talks to whom?').reason, 'metadata:question');
  assert.equal(get('This helper text needs review').classification, 'review');
  assert.equal(get('Could not open capture').reason, 'stored-state-message');
  assert.equal(get('Open details').migration, 'safe-jsx');
  assert.equal(get('Inspect a host').classification, 'display');
  assert.equal(get('Close').migration, 'safe-jsx');
  assert.equal(get('Showing ').fragmented, true);
  assert.deepEqual(get('Found {arg0} packets').expressions, [{ name: 'arg0', expression: 'count' }]);
  assert.equal(result.formatting.length, 1);
});

test('stable keys are independent of source locations and preserve contextual ambiguity', () => {
  assert.equal(stableKey('Close'), stableKey('Close'));
  assert.notEqual(stableKey('Open', 'verb'), stableKey('Open', 'status'));
  assert.equal(jsxText('\n  Capture &amp; inspect\n  packets\n'), 'Capture & inspect packets');
  const title = scanSource('function Panel() { return <span title="Capture &amp; inspect" />; }').occurrences.find(item => item.reason === 'jsx-attribute:title');
  assert.equal(title.source, 'Capture & inspect');
});

test('migration preserves data IDs and state, inserts a subscription before early returns and refuses stale/parent files', () => {
  const text = `import React from 'react';\nexport function Panel() { const [value, setValue] = useState(''); if (!ready) return null; return <button value="capture" aria-label="Close panel">Close</button>; }`;
  const file = { repo: 'netcap-pro', file: 'frontend/src/components/Panel.tsx', sha256: digest(text), ...scanSource(text) };
  const selected = Object.fromEntries(file.occurrences.filter(item => item.migration === 'safe-jsx').map(item => [item.id, `ui:${item.key}`]));
  const plan = planFile(file, text, selected);
  assert.match(plan.text, /value="capture"/);
  assert.match(plan.text, /aria-label=\{__netcapT\("ui:m_/);
  assert.match(plan.text, /const \[value, setValue\] = useState\(''\)/);
  assert.ok(plan.text.indexOf('const __netcapT =') < plan.text.indexOf('if (!ready)'));
  assert.equal(scanSource(plan.text).occurrences.filter(item => item.reason === 'message-call').length, 2);
  assert.throws(() => planFile(file, text + ' ', selected), /changed since inventory/);
  assert.throws(() => planFile({ ...file, file: 'frontend/src/main.tsx' }, text, selected), /Parent-owned/);
});

test('module metadata and stored-state strings stay in the review queue', () => {
  const text = `const items = [{label: 'Keep me reactive'}]; function Panel() {setError('Deferred error'); return <div>Done</div>;}`;
  const file = { repo: 'netcap', file: 'Panel.tsx', sha256: digest(text), formatting: [], dynamicUI: [], ...scanSource(text) };
  const snapshot = { files: [file] };
  const staging = extract(snapshot);
  assert.equal(Object.keys(staging.messages).length, 1);
  assert.equal(staging.pending.length, 2);
  assert.ok(completionFindings(snapshot, { occurrences: {} }).length > 0);
  const occurrence = file.occurrences.find(item => item.source === 'Keep me reactive');
  assert.throws(() => planFile(file, text, { [occurrence.id]: 'ui:test' }), /reviewed source migration/);
  const nested = scanSource('function Panel() { return <span>{translate("ui:title", { value: name || "Unknown author" })}</span>; }');
  assert.equal(nested.occurrences.find(item => item.source === 'ui:title').classification, 'localized');
  assert.notEqual(nested.occurrences.find(item => item.source === 'Unknown author').classification, 'localized');
});

test('HTML bootstrap reviews require the exact reviewed document and do not exempt new English controls', () => {
  const source = '<title>Netcap</title><div id="root"></div>';
  const file = { repo: 'netcap', file: 'index.html', sha256: digest(source), occurrences: [], html: { source } };
  const review = { reason: 'Brand-only bootstrap; the host localizes document metadata before mounting.', sha256: file.sha256 };
  const decisions = { html: { 'netcap/index.html': review } };
  assert.equal(completionFindings({ files: [file] }, {}).length, 1);
  assert.equal(completionFindings({ files: [file] }, decisions).length, 0);
  const changed = { ...file, sha256: digest(source + '<button>Unreviewed English control</button>') };
  assert.equal(completionFindings({ files: [changed] }, decisions).length, 1);
  const control = { repo: 'netcap', file: 'Panel.tsx', ...scanSource('function Panel() { return <button>Unreviewed English control</button>; }') };
  assert.ok(completionFindings({ files: [control] }, decisions).some(item => item.kind === 'display'));
});

test('the completion gate rejects descriptor string coercion but accepts explicit rendering and deferred composition', () => {
  const text = [
    "import { message as deferred, errorText, metadataMessage, renderText, joinMessages } from './i18n';",
    "setFailure(String(errorText(error) || error));",
    "setSuccess(metadataMessage(result, 'message') + ' - ' + result.warning);",
    'setNotice(`${deferred("ui:known")}`);',
    "setSuccess(joinMessages([metadataMessage(result, 'message'), result.warning], ' - '));",
    "const visible = String(renderText(errorText(error)));",
    "const caption = `${renderText(deferred('ui:known'))} suffix`;",
  ].join('\n');
  const file = { repo: 'netcap', file: 'fixture.tsx', ...scanSource(text) };
  assert.equal(file.messageCoercions.length, 3);
  const findings = completionFindings({ files: [file] }, {});
  assert.equal(findings.filter(item => item.kind === 'messageCoercions').length, 3);
});

test('ICU validation rejects lost variables, select IDs, offsets, number styles, English filler and altered technical tokens', () => {
  assert.throws(() => validateTranslation('Open {name}', 'Öffnen', 'de'), /mismatch/);
  assert.throws(() => validateTranslation('Close', 'Close', 'de'), /English/);
  assert.doesNotThrow(() => validateTranslation('Inspect PCAP', 'PCAP prüfen', 'de', { tokens: ['PCAP'] }));
  assert.throws(() => validateTranslation('Inspect PCAP', 'Paketaufzeichnung prüfen', 'de', { tokens: ['PCAP'] }), /token changed/);
  assert.throws(() => validateTranslation('{kind, select, raw {Raw} other {Other}}', '{kind, select, roh {Roh} other {Andere}}', 'de'), /mismatch/);
  assert.throws(() => validateTranslation('{n, plural, offset:1 one {# item} other {# items}}', '{n, plural, one {# Element} other {# Elemente}}', 'de'), /mismatch/);
  assert.throws(() => validateTranslation('{n, number, ::percent}', '{n, number}', 'de'), /mismatch/);
  assert.doesNotThrow(() => validateTranslation('{n, plural, one {# packet} other {# packets}}', '{n, plural, other {# 个数据包}}', 'zh-Hans'));
  assert.doesNotThrow(() => validateTranslation('{n, plural, one {# SMB host} other {# SMB hosts}}', '{n, plural, other {# 台 SMB 主机}}', 'zh-Hans', { tokens: ['SMB'] }));
  assert.throws(() => validateTranslation('{n, plural, one {# SMB host} other {# SMB hosts}}', '{n, plural, other {# 台主机}}', 'zh-Hans', { tokens: ['SMB'] }), /token changed/);
  assert.throws(() => validateTranslation('{kind, select, tcp {TCP} other {UDP}}', '{kind, select, tcp {UDP 已选} other {TCP 已选}}', 'zh-Hans', { tokens: ['TCP', 'UDP'] }), /token changed/);
  assert.throws(() => validateTranslation('<link>Copy</link>', '<link>Kopieren</link><link>Kopieren</link>', 'de'), /Named tag count/);
  assert.doesNotThrow(() => validateTranslation('{n, plural, one {<link>Copy</link>} other {<link>Copies</link>}}', '{n, plural, other {<link>复制</link>}}', 'zh-Hans'));
  assert.throws(() => signature('{n, plural, one {#} other {#}}', 'zh-Hans'), /plural category/);
  assert.throws(() => validateCatalogObject({ key: { en: 'nested' } }), /non-text/);
  assert.doesNotThrow(() => validateCatalogObject({ 'removed:pro.graph.machine.tls-analysis.step.step-1-tls.name': 'TLS analysis' }, 'backend IDs', { qualified: true }));
  assert.throws(() => validateCatalogObject({ 'ui:constructor': 'Invalid' }, 'backend IDs', { qualified: true }), /invalid key/);
  assert.throws(() => validateCatalogObject({ 'ui:../escaped': 'Invalid' }, 'backend IDs', { qualified: true }), /invalid key/);
});

test('translation requests are bounded, validated and checkpoint publication requires all five target catalogs', async () => {
  const batch = { 'ui:test': { namespace: 'ui', key: 'test', message: 'Close', context: '' } };
  let calls = 0;
  const response = await translateBatch(batch, 'de', {
    key: 'test-only-key', model: 'test-model', policy: {}, glossary: {}, sleep: async () => {},
    fetchImpl: async () => { calls++; return { ok: true, json: async () => ({ modelVersion: 'fake-test-version', candidates: [{ finishReason: 'STOP', content: { parts: [{ text: '{"ui:test":"Schließen"}' }] } }] }) }; },
  });
  assert.equal(calls, 1);
  assert.equal(response.translated['ui:test'], 'Schließen');
  calls = 0;
  await assert.rejects(() => translateBatch(batch, 'de', {
    key: 'test-only-key', model: 'test-model', policy: {}, glossary: {}, sleep: async () => {},
    fetchImpl: async () => { calls++; return { ok: false, status: 503 }; },
  }), /bounded attempts/);
  assert.equal(calls, 3);
  assert.throws(() => validateBatch(batch, { 'ui:other': 'Schließen' }, 'de', {}), /missing\/extra/);
  const staging = { messages: batch };
  assert.throws(() => prepareCatalogs(staging, { sourceHash: digest(JSON.stringify(batch)), translations: { de: response.translated } }, {}, {}), /expected a flat JSON object/);
});

test('the current capture chooser, connection sources and host controls resolve in all six offline catalogs', () => {
  const deferred = sourceCalls("setNotice(message('Deferred host copy')); richText('Rich host copy'); i18nMessage('ui:known'); rawCode('TCP');");
  assert.deepEqual([...deferred.keys()], ['Deferred host copy', 'Rich host copy', 'ui:known']);
  const chooser = sourceCalls(fs.readFileSync(path.join(pro, 'frontend/src/components/OpenCaptureButton.tsx'), 'utf8'));
  assert.equal(chooser.size, 22);
  assert.ok([...chooser.keys()].every(source => !source.includes('file(s)')));
  const source = JSON.parse(fs.readFileSync(path.join(catalogsRoot, 'ui/en.json'), 'utf8'));
  const aliases = JSON.parse(fs.readFileSync(path.join(catalogsRoot, 'ui/sources.json'), 'utf8'));
  const catalogs = Object.fromEntries(locales.map(locale => [locale, JSON.parse(fs.readFileSync(path.join(catalogsRoot, `ui/${locale}.json`), 'utf8'))]));
  const bySource = new Map(Object.entries(source).map(([key, value]) => [value, key]));
  for (const [key, value] of Object.entries(aliases)) if (!bySource.has(value)) bySource.set(value, key);
  for (const message of [...chooser.keys(), ...Object.values(preferenceSources), 'Connecting to NETCAP...', 'Connecting to backend...', 'Connection lost. Reconnecting...']) {
    const key = bySource.get(message); assert.ok(key, `missing source: ${message}`);
    for (const locale of locales) assert.ok(catalogs[locale][key], `${locale}/${message}`);
  }
  const ids = JSON.parse(fs.readFileSync(path.join(frontend, 'packages/netcap-ui/src/lib/i18n/backend-ids.json'), 'utf8'));
  assert.ok(ids['config.option.input.label']);
  assert.ok(ids['feature.dns-resolution-context.title']);
  assert.ok(ids['chart.field.DstPort.description']);
});

test('1.7.0 release copy is translated in every locale with store-only capture wording in the shared catalog', () => {
  const entries = releaseEntries('1.7.0');
  assert.equal(Object.keys(entries).length, 7);
  assert.equal(Object.values(entries).filter(entry => entry.namespace === 'ui').length, 6);
  const ui = JSON.parse(fs.readFileSync(path.join(catalogsRoot, 'ui/en.json'), 'utf8'));
  for (const entry of Object.values(entries)) {
    for (const locale of locales) {
      const catalog = JSON.parse(fs.readFileSync(path.join(catalogsRoot, entry.namespace, `${locale}.json`), 'utf8'));
      assert.ok(catalog[entry.key], `${locale}/${entry.key}`);
      if (locale !== 'en') validateTranslation(entry.message, catalog[entry.key], locale);
    }
    if (entry.message.includes('Linux drag and drop')) {
      assert.equal(entry.namespace, 'removed');
      assert.equal(Object.values(ui).includes(entry.message), false);
    }
  }
  const store = JSON.parse(fs.readFileSync(path.join(pro, 'frontend/src/lib/releaseHighlights.appstore.json'), 'utf8'))['1.7.0'];
  assert.equal(store.length, 3);
  assert.ok(store.every(entry => !/Windows|Linux|graph/i.test(entry.description)));
});
