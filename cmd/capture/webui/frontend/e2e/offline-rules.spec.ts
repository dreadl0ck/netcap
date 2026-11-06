import { expect, test, type Page, type Route } from '@playwright/test';
import type { OfflineAlertMetadata, OfflinePack } from '../packages/netcap-ui/src/lib/api';

const yaml = 'format: netcap-offline-rules/v1\nrules: []\n# synthetic uploaded fixture';
const pack: OfflinePack = { format: 'netcap-offline-rules/v1', rules: [{ id: 'fixture', name: 'HTTPS fixture', type: 'TCP', expression: 'DstPort == 443', severity: 'medium', enabled: true, threshold: { count: 2, window: '60s', groupBy: ['DstPort'] } }] };
const metadata: OfflineAlertMetadata = {
  version: 1, eventId: 'event-fixture', runId: 'run-fixture', ruleId: 'fixture', ruleDigest: 'digest', inputCanonicalDigest: 'canonical',
  group: { SrcIP: '192.0.2.1', DstPort: { type: 'int32', value: '443' } }, count: 2, first: '1794000000000000001', last: '1794000000000000003', windowNs: '60000000000',
  contributors: [{ file: 'TCP.ncap.gz', ordinal: '9007199254740993', sha256: 'record-digest', timestamp: '1794000000000000001' }], contributorsTruncated: false,
};

async function backend(page: Page, baseURL: string) {
  const calls: { method: string; path: string; query: string; body: any }[] = [];
  const unexpected: string[] = [];
  const errors: string[] = [];
  const state = { available: true, valid: true, enabled: true, processing: false, live: false, sessionId: '', history: [] as any[],
    execution: { status: 200, json: { report: { status: 'complete', committedAlerts: 0 } } as any },
    execute: undefined as undefined | ((route: Route) => Promise<void>), validate: undefined as undefined | ((route: Route) => Promise<void>),
  };
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', msg => { if (msg.type() === 'error' && !msg.text().startsWith('Failed to load resource: the server responded with a status of')) errors.push(msg.text()); });
  await page.context().routeWebSocket('**/*', ws => { unexpected.push(`WebSocket ${ws.url()}`); ws.close(); });
  await page.context().route('**/*', async route => {
    const req = route.request(); const url = new URL(req.url());
    if (url.origin !== baseURL) { unexpected.push(req.url()); return route.abort(); }
    if (!url.pathname.startsWith('/api/')) return route.continue();
    calls.push({ method: req.method(), path: url.pathname, query: url.search, body: req.postData() ? req.postDataJSON() : null });
    const key = `${req.method()} ${url.pathname}`;
    let json: any;
    let status = 200;
    switch (key) {
      case 'GET /api/status': json = { activeInputFile: '/fixture.pcap', outputDir: '/fixture', isProcessing: state.processing, isLiveMode: state.live, sessionId: state.sessionId }; break;
      case 'GET /api/files/input': json = [{ path: '/fixture.pcap', name: 'fixture.pcap', isCompleted: !state.processing }]; break;
      case 'GET /api/version': json = { version: 'ui-mocked' }; break;
      case 'GET /api/menu-counts': json = {}; break;
      case 'GET /api/dbs/status': json = { satisfied: true, missing: [] }; break;
      case 'GET /api/rules': json = { rules: [] }; break;
      case 'GET /api/rules/offline/packs': status = state.available ? 200 : 404; json = state.available ? { packs: [{ name: 'Disabled TCP example', yaml: 'disabled-example' }], limits: { maxRecords: 100 } } : { error: 'not found' }; break;
      case 'GET /api/rules/offline/evaluations': json = { evaluations: state.history }; break;
      case 'POST /api/rules/offline/validate':
        if (state.validate) return state.validate(route);
        status = state.valid ? 200 : 400;
        json = { valid: state.valid, errors: state.valid ? [] : [{ field: 'yaml', message: 'invalid threshold' }], pack: { ...pack, rules: pack.rules.map(rule => ({ ...rule, enabled: state.enabled })) } }; break;
      case 'POST /api/rules/offline/execute':
        if (state.execute) return state.execute(route);
        ({ status, json } = state.execution); break;
      case 'GET /api/network-detection': json = { schema: 1, active: false, events: 0, alerts: 0 }; break;
      case 'GET /api/alerts/stats': json = { totalAlerts: 1, groupCount: 1, bySeverity: { medium: 1 }, byRule: { 'HTTPS fixture': 1 }, recentAlerts: [], criticalAlerts: 0, lastUpdate: 1794000000 }; break;
      case 'GET /api/alerts/grouped': {
        const alert = { timestamp: 1794000000000000000, name: 'HTTPS fixture', description: 'Synthetic offline alert', ruleName: 'HTTPS fixture', recordType: 'TCP', severity: 'medium', tags: [], mitre: '', srcIP: '192.0.2.1', dstIP: '192.0.2.2', matchedRecord: '{"DstPort":443}', ruleExpression: 'DstPort == 443', threshold: 2, thresholdWindow: 60, resolved: false, alertId: 'event-fixture', groupedEvaluation: metadata };
        json = { groups: [{ ...alert, groupId: 'group-fixture', count: 1, firstSeen: alert.timestamp, lastSeen: alert.timestamp, uniqueSrcIPs: [alert.srcIP], uniqueDstIPs: [alert.dstIP], uniqueSrcPorts: [], uniqueDstPorts: ['443'], sampleAlerts: [alert], resolvedCount: 0 }], totalCount: 1, groupCount: 1 }; break;
      }
      default: unexpected.push(key); return route.abort();
    }
    return route.fulfill({ status, json });
  });
  return { state, calls, async clean() {
    await test.info().attach('ui-mocked-ledger', { body: JSON.stringify({ calls, unexpected, errors }, null, 2), contentType: 'application/json' });
    expect(unexpected, 'undeclared API calls/egress').toEqual([]);
    expect(errors, 'browser errors').toEqual([]);
  } };
}

async function upload(page: Page) {
  await page.getByLabel('Upload offline YAML pack').setInputFiles({ name: 'fixture.yaml', mimeType: 'text/yaml', buffer: Buffer.from(yaml) });
  await expect(page.getByRole('button', { name: 'Validate pack', exact: true })).toBeEnabled();
}
async function validate(page: Page) {
  await upload(page);
  await page.getByRole('button', { name: 'Validate pack', exact: true }).click();
  await expect(page.getByText('Pack validated. Ready for explicit evaluation.')).toBeVisible();
}

test('ui-mocked: capability 404 never falls back to legacy execution', async ({ page, baseURL }) => {
  const b = await backend(page, baseURL!); b.state.available = false;
  await page.goto('/rules');
  await expect(page.getByText('Offline evaluation is unavailable on this backend.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Evaluate capture', exact: true })).toHaveCount(0);
  expect(b.calls.filter(call => call.method === 'POST')).toEqual([]);
  await b.clean();
});

test('ui-mocked: upload size/read failures never reuse a previously validated pack', async ({ page, baseURL }) => {
  const b = await backend(page, baseURL!);
  await page.goto('/rules'); await validate(page);
  await page.getByLabel('Upload offline YAML pack').setInputFiles({ name: 'large.yaml', mimeType: 'text/yaml', buffer: Buffer.alloc((1 << 20) + 1, 'x') });
  await expect(page.getByText('Pack upload exceeds 1 MiB.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Evaluate capture', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Validate pack', exact: true })).toBeDisabled();
  await page.evaluate(() => { File.prototype.text = async () => { throw new Error('Synthetic file read failure'); }; });
  await page.getByLabel('Upload offline YAML pack').setInputFiles({ name: 'broken.yaml', mimeType: 'text/yaml', buffer: Buffer.from(yaml) });
  await expect(page.getByText('Error: Synthetic file read failure')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Evaluate capture', exact: true })).toBeDisabled();
  expect(b.calls.filter(c => c.path.endsWith('/execute'))).toHaveLength(0);
  await b.clean();
});

test('ui-mocked: service selection sends sessionId without a local inputFile fallback', async ({ page, baseURL }) => {
  const b = await backend(page, baseURL!); b.state.sessionId = 'owned-fixture-session';
  await page.goto('/rules'); await validate(page);
  await page.getByRole('button', { name: 'Evaluate capture', exact: true }).click();
  await expect(page.getByText('Offline evaluation completed', { exact: true })).toBeVisible();
  expect(b.calls.find(c => c.path.endsWith('/execute'))?.body).toEqual({ yaml, sessionId: 'owned-fixture-session' });
  expect(b.calls.filter(c => c.path.endsWith('/evaluations')).every(c => c.query === '?sessionId=owned-fixture-session')).toBe(true);
  await b.clean();
});

test('ui-mocked: browser File.text, keyboard validation, explicit frozen selector and zero-alert completion', async ({ page, baseURL }) => {
  const b = await backend(page, baseURL!);
  await page.goto('/rules'); await upload(page);
  await page.getByText('fixture.yaml (read-only YAML)').click();
  await expect(page.locator('pre').filter({ hasText: 'synthetic uploaded fixture' })).toHaveText(yaml);
  const button = page.getByRole('button', { name: 'Validate pack', exact: true });
  await button.focus(); await page.keyboard.press('Enter');
  await expect(page.getByText('Pack validated. Ready for explicit evaluation.')).toBeVisible();
  expect(b.calls.filter(c => c.path.endsWith('/execute'))).toHaveLength(0);
  await page.getByRole('button', { name: 'Evaluate capture', exact: true }).click();
  await expect(page.getByText('Offline evaluation completed', { exact: true })).toBeVisible();
  await expect(page.getByText('0 alerts committed')).toBeVisible();
  expect(b.calls.find(c => c.path.endsWith('/validate'))?.body).toEqual({ yaml });
  expect(b.calls.find(c => c.path.endsWith('/execute'))?.body).toEqual({ yaml, inputFile: '/fixture.pcap' });
  expect(b.calls.filter(c => c.path.endsWith('/evaluations')).every(c => c.query === '?inputFile=%2Ffixture.pcap')).toBe(true);
  await b.clean();
});

test('ui-mocked: invalid and all-disabled packs cannot execute; upload resets validation', async ({ page, baseURL }) => {
  const b = await backend(page, baseURL!); b.state.valid = false;
  await page.goto('/rules'); await upload(page);
  await page.getByRole('button', { name: 'Validate pack', exact: true }).click();
  await expect(page.getByText('Validation failed: yaml: invalid threshold')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Evaluate capture', exact: true })).toBeDisabled();
  b.state.valid = true; b.state.enabled = false;
  await page.getByRole('button', { name: 'Disabled TCP example', exact: true }).click();
  await page.getByRole('button', { name: 'Validate pack', exact: true }).click();
  await expect(page.getByText(/Pack validated, but all rules are disabled/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Evaluate capture', exact: true })).toBeDisabled();
  b.state.enabled = true; await validate(page); await upload(page);
  await expect(page.getByRole('button', { name: 'Evaluate capture', exact: true })).toBeDisabled();
  expect(b.calls.filter(c => c.path.endsWith('/execute'))).toHaveLength(0);
  await b.clean();
});

test('ui-mocked: validating/evaluating busy gates and cancellation recover without claiming completion', async ({ page, baseURL }) => {
  const b = await backend(page, baseURL!);
  let releaseValidation!: () => void;
  const pendingValidation = new Promise<void>(resolve => { releaseValidation = resolve; });
  b.state.validate = async route => { await pendingValidation; await route.fulfill({ json: { valid: true, errors: [], pack } }); };
  let releaseExecution!: () => void;
  const pendingExecution = new Promise<void>(resolve => { releaseExecution = resolve; });
  b.state.execute = async route => { await pendingExecution; await route.fulfill({ json: { report: { status: 'complete', committedAlerts: 0 } } }).catch(() => {}); };
  try {
    await page.goto('/rules'); await upload(page);
    await page.getByRole('button', { name: 'Validate pack', exact: true }).click();
    await expect(page.getByRole('status')).toHaveText('Validating pack…');
    await expect(page.getByRole('button', { name: 'Validate pack', exact: true })).toBeDisabled();
    releaseValidation(); await expect(page.getByText('Pack validated. Ready for explicit evaluation.')).toBeVisible();
    await page.getByRole('button', { name: 'Evaluate capture', exact: true }).click();
    await expect(page.getByRole('status')).toHaveText('Evaluating selected capture…');
    await expect(page.getByRole('button', { name: 'Evaluate capture', exact: true })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Validate pack', exact: true })).toBeDisabled();
    const cancel = page.getByRole('button', { name: 'Cancel evaluation', exact: true });
    await cancel.focus(); await page.keyboard.press('Enter');
    await expect(page.getByText('Evaluation cancelled. Check execution history for persisted partial coverage.')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Evaluate capture', exact: true })).toBeEnabled();
    await expect(page.getByText('Offline evaluation completed', { exact: true })).toHaveCount(0);
    expect(b.calls.filter(c => c.path.endsWith('/execute'))).toHaveLength(1);
    await b.clean();
  } finally { releaseValidation(); releaseExecution(); }
});

for (const scenario of ['partial', 'publish-failed', 'read-error', 'busy'] as const) {
  test(`ui-mocked: ${scenario} remains distinct from successful empty evaluation`, async ({ page, baseURL }) => {
    const b = await backend(page, baseURL!);
    b.state.execution = scenario === 'busy' ? { status: 409, json: { error: 'Capture output is busy' } }
      : scenario === 'read-error' ? { status: 422, json: { error: 'record read failed', report: null } }
      : { status: scenario === 'publish-failed' ? 422 : 200, json: { error: scenario === 'publish-failed' ? 'alert publication failed' : undefined, report: { status: scenario, error: 'coverage fixture', committedAlerts: 0 } } };
    b.state.history = [{ status: 'partial', error: 'persisted partial fixture' }];
    await page.goto('/rules'); await validate(page);
    await page.getByRole('button', { name: 'Evaluate capture', exact: true }).click();
    if (scenario === 'busy') await expect(page.getByText(/Capture output is busy/)).toBeVisible();
    else if (scenario === 'read-error') await expect(page.getByText('Evaluation failed: record read failed')).toBeVisible();
    else await expect(page.getByRole('alert').filter({ hasText: `Incomplete offline evaluation: ${scenario}. Coverage is not complete.` }).filter({ visible: true })).toHaveCount(1);
    if (scenario === 'publish-failed') await expect(page.getByText('Evaluation failed: alert publication failed')).toBeVisible();
    await expect(page.getByText('Offline evaluation completed', { exact: true })).toHaveCount(0);
    await expect(page.getByText(/Execution history includes incomplete coverage/)).toBeVisible();
    await page.getByText('Execution history (1)', { exact: true }).click();
    await expect(page.locator('pre').filter({ hasText: 'persisted partial fixture' })).toBeVisible();
    await b.clean();
  });
}

for (const flag of ['processing', 'live'] as const) {
  test(`ui-mocked: ${flag} capture is gated after validation`, async ({ page, baseURL }) => {
    const b = await backend(page, baseURL!); b.state[flag] = true;
    await page.goto('/rules'); await validate(page);
    await expect(page.getByRole('button', { name: 'Evaluate capture', exact: true })).toBeDisabled();
    expect(b.calls.filter(c => c.path.endsWith('/execute'))).toHaveLength(0);
    await b.clean();
  });
}

test('ui-mocked: Alerts sample preserves string-valued group and nanosecond audit metadata exactly', async ({ page, baseURL }) => {
  const b = await backend(page, baseURL!);
  await page.goto('/alerts');
  await page.getByRole('row').filter({ hasText: 'HTTPS fixture' }).click();
  await page.getByRole('button', { name: 'View Sample 1', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText('2 matching records · rule fixture')).toBeVisible();
  const pre = dialog.locator('pre').filter({ hasText: 'event-fixture' });
  expect(JSON.parse(await pre.innerText())).toEqual(metadata);
  await page.keyboard.press('Escape'); await expect(dialog).toHaveCount(0);
  await b.clean();
});
