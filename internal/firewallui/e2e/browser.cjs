// Manually invoked by TestBrowser against its owned local services and databases.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { chromium, expect } = require(process.env.FIREWALL_PLAYWRIGHT_MODULE);
const env = process.env;
const origins = ['UI_ORIGIN', 'READONLY_ORIGIN', 'FLEET_ORIGIN', 'LEASE_ORIGIN', 'TRAFFIC_ORIGIN', 'AUTH_ORIGIN'].map(k => env[k]);
let browser;
let contextID = 0;
before(async () => {
  browser = await chromium.launch({ headless: true });
  for (const origin of origins.filter(o => o !== env.TRAFFIC_ORIGIN)) {
    const identity = await (await fetch(origin + '/fixture/identity')).json();
    assert.equal(identity.run_id, env.RUN_ID, 'must own this server');
  }
});
after(async () => { await browser?.close(); });
async function session(origin, token = env.UI_TOKEN) {
  const context = await browser.newContext({ serviceWorkers: 'block' });
  const id = ++contextID;
  await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
  const violations = [], errors = [];
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    if (!origins.includes(url.origin)) { violations.push(url.origin); return route.abort('blockedbyclient'); }
    return route.continue();
  });
  const page = await context.newPage();
  page.on('pageerror', err => errors.push(err.message));
  await page.goto(origin + '/console/');
  await page.getByLabel('Bearer token', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Log out', exact: true })).toBeVisible();
  return { page, context, async close() { await context.tracing.stop({ path: `${env.UI_ARTIFACTS}/context-${id}.zip` }); await context.close(); assert.deepEqual(errors, []); assert.deepEqual(violations, []); } };
}
async function control(origin, op, body) {
  const response = await fetch(origin + '/api/v1/policy/' + op, {
    method: body ? 'POST' : 'GET', headers: { Authorization: 'Bearer ' + env.UI_TOKEN, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  });
  return { status: response.status, data: await response.json() };
}
async function completed(page) { await expect(page.getByRole('status')).toHaveText('Operation completed.'); }
async function accept(page, button) {
  await button.click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.getByRole('button', { name: 'Confirm', exact: true }).click();
}
const bundle = id => ({ version: '1', id, mode: 'enforce', default: 'allow', rules: [{ id: 'blocked', phase: 'request', expression: 'Path == "/blocked"', action: 'deny', status: 403, priority: 1 }] });

test('scoped identity: exact-origin console reads, server RBAC denies writes, token stays in memory', async () => {
  const s = await session(env.AUTH_ORIGIN), { page } = s;
  try {
    await expect(page.locator('#active')).not.toHaveText('');
    await page.getByLabel('Bundle source · JSON or YAML', { exact: true }).fill(JSON.stringify(bundle('reader-denied')));
    await page.getByRole('button', { name: 'Stage revision', exact: true }).click();
    await expect(page.getByRole('status')).toContainText('HTTP 403');
    const denied = await page.evaluate(async () => {
      const response = await fetch('/api/v1/policy/stage', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      return response.status;
    });
    assert.equal(denied, 403, 'browser request without bearer cannot use the console wrapper');
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    await page.reload();
    await expect(page.getByLabel('Bearer token', { exact: true })).toBeVisible();
    assert.equal(await page.getByLabel('Bearer token', { exact: true }).inputValue(), '');
  } finally { await s.close(); }
});

test('policy: invalid source cannot activate; YAML stage, diff, replay, activate, real traffic and persisted reload', async () => {
  const s = await session(env.UI_ORIGIN), { page } = s;
  try {
    const start = (await control(env.UI_ORIGIN, 'revision')).data.revision;
    await page.getByLabel('Bundle source · JSON or YAML', { exact: true }).fill('{"version":"broken"}');
    await page.getByRole('button', { name: 'Check bundle', exact: true }).click();
    await expect(page.getByRole('status')).toContainText('HTTP 400');
    await expect(page.getByRole('button', { name: 'Activate pending', exact: true })).toBeDisabled();
    assert.equal((await control(env.UI_ORIGIN, 'revision')).data.revision, start);
    const yaml = '# preserve this comment\nversion: "1"\nid: browser-yaml\nmode: enforce\ndefault: allow\nrules:\n  - id: blocked\n    phase: request\n    expression: Path == "/blocked"\n    action: deny\n    status: 403\n';
    const source = page.getByLabel('Bundle source · JSON or YAML', { exact: true });
    await source.fill(yaml);
    await page.getByRole('button', { name: 'Check bundle', exact: true }).click(); await completed(page);
    assert.equal(await source.inputValue(), yaml, 'checking must preserve source byte for byte');
    await page.getByRole('button', { name: 'Stage revision', exact: true }).click(); await completed(page);
    const staged = await page.locator('#pending').textContent();
    assert.notEqual(staged, start);
    assert.equal((await control(env.UI_ORIGIN, 'revision')).data.revision, start, 'stage does not activate');
    await page.getByRole('button', { name: 'Compare with active', exact: true }).click(); await completed(page);
    await expect(page.getByLabel('Policy operation result')).toContainText('changed_fields');
    await page.getByText('Replay & explain', { exact: true }).click();
    await page.getByRole('button', { name: 'Replay selected revision', exact: true }).click(); await completed(page);
    await expect(page.getByLabel('Policy operation result')).toContainText('deny');
    await accept(page, page.getByRole('button', { name: 'Activate pending', exact: true })); await completed(page);
    const before = await (await fetch(env.UI_ORIGIN + '/fixture/identity')).json();
    assert.equal((await fetch(env.TRAFFIC_ORIGIN + '/blocked')).status, 403);
    const denied = await (await fetch(env.UI_ORIGIN + '/fixture/identity')).json();
    assert.equal(denied.origin_calls, before.origin_calls, 'denied traffic never reached origin');
    assert.equal((await fetch(env.TRAFFIC_ORIGIN + '/allowed')).status, 204);
    const allowed = await (await fetch(env.UI_ORIGIN + '/fixture/identity')).json();
    assert.equal(allowed.origin_calls, before.origin_calls + 1);
    await page.reload();
    await expect(page.getByLabel('Bearer token', { exact: true })).toBeVisible();
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    await page.getByLabel('Bearer token', { exact: true }).fill(env.UI_TOKEN);
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
    await expect(page.locator('#active')).toHaveText(staged);
    assert.equal((await control(env.UI_ORIGIN, 'revision')).data.revision, staged);
  } finally { await s.close(); }
});

test('policy: native form retains advanced fields, stale CAS fails, rollback uses CAS', async () => {
  const s = await session(env.UI_ORIGIN), { page } = s;
  try {
    const initial = (await control(env.UI_ORIGIN, 'revision')).data.revision;
    const native = bundle('native-form'); native.defaults = { response: 'allow' };
    native.rules[0].threshold = { count: 2, window: '1m', group_by: 'ClientIP' };
    await page.getByLabel('Bundle source · JSON or YAML', { exact: true }).fill(JSON.stringify(native));
    await page.getByText('Native bundle form', { exact: true }).click();
    await page.getByRole('button', { name: 'Load JSON into form', exact: true }).click(); await completed(page);
    await page.getByLabel('Bundle ID', { exact: true }).fill('form-edited');
    await page.getByLabel('expression · rule 1', { exact: true }).fill('Path == "/different"');
    await page.getByRole('button', { name: 'Apply form to source', exact: true }).click();
    const edited = JSON.parse(await page.getByLabel('Bundle source · JSON or YAML', { exact: true }).inputValue());
    assert.deepEqual(edited.rules[0].threshold, native.rules[0].threshold); assert.deepEqual(edited.defaults, native.defaults);
    assert.equal(edited.id, 'form-edited'); assert.equal(edited.rules[0].expression, 'Path == "/different"');
    await page.getByRole('button', { name: 'Stage revision', exact: true }).click(); await completed(page);
    const oldExpected = await page.locator('#expected').inputValue();
    const rival = await control(env.UI_ORIGIN, 'stage', { bundle: JSON.stringify(bundle('rival')), idempotency_key: 'rival-stage' }); assert.equal(rival.status, 200);
    const winner = await control(env.UI_ORIGIN, 'activate', { revision: rival.data.revision, expected_revision: oldExpected, idempotency_key: 'rival-activate' }); assert.equal(winner.status, 200);
    await accept(page, page.getByRole('button', { name: 'Activate pending', exact: true }));
    await expect(page.getByRole('status')).toContainText('HTTP 409');
    assert.equal((await control(env.UI_ORIGIN, 'revision')).data.revision, rival.data.revision);
    await page.getByRole('button', { name: 'Refresh status', exact: true }).click(); await completed(page);
    await page.getByLabel('Revision to inspect or roll back to', { exact: true }).selectOption(initial);
    await accept(page, page.getByRole('button', { name: 'Roll back to selected', exact: true })); await completed(page);
    assert.equal((await control(env.UI_ORIGIN, 'revision')).data.revision, initial);
  } finally { await s.close(); }
});

test('auth: read-only mode returns server 403; logout clears memory and rejects unauthorized control', async () => {
  const s = await session(env.READONLY_ORIGIN), { page } = s;
  try {
    await page.getByRole('button', { name: 'Stage revision', exact: true }).click();
    await expect(page.getByRole('status')).toContainText('HTTP 403');
    await page.getByRole('button', { name: 'Log out', exact: true }).click();
    await expect(page.getByRole('status')).toContainText('Logged out');
    assert.equal(await page.locator('#bundle').inputValue(), '');
    const result = await page.evaluate(async () => {
      const r = await fetch('/api/v1/policy/activate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); return r.status;
    });
    assert.ok([401,403].includes(result));
    const bad = await fetch(env.READONLY_ORIGIN + '/api/v1/policy/revision', { headers: { Authorization: 'Bearer incorrect' } }); assert.equal(bad.status, 401);
    const cross = await fetch(env.READONLY_ORIGIN + '/api/v1/policy/stage', { method: 'POST', headers: { Authorization: 'Bearer ' + env.UI_TOKEN, Origin: 'https://evil.invalid', 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(cross.status, 403); assert.equal(cross.headers.get('access-control-allow-origin'), null);
    await page.getByLabel('Bearer token', { exact: true }).fill('incorrect');
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
    await expect(page.getByRole('status')).toContainText('HTTP 401');
    await expect(page.getByRole('button', { name: 'Log out', exact: true })).toBeHidden();
  } finally { await s.close(); }
});

test('fleet: scoped listing isolates tenant; drain/revoke change desired but not observed; foreign scope returns 403', async () => {
  const s = await session(env.FLEET_ORIGIN, 'synthetic-scoped-token'), { page } = s;
  try {
    await page.getByLabel('Tenant', { exact: true }).fill('tenant-a'); await page.getByLabel('Application', { exact: true }).fill('app');
    await page.getByRole('button', { name: 'Load scoped fleet', exact: true }).click();
    await expect(page.getByRole('status')).toHaveText('Scoped fleet loaded.');
    await expect(page.locator('#targets')).toContainText('edge-a'); await expect(page.locator('#targets')).not.toContainText('foreign');
    await page.getByText('Stage & roll out', { exact: true }).click();
    await page.getByLabel('Fleet bundle · JSON or YAML', { exact: true }).fill(JSON.stringify(bundle('fleet-browser')));
    await page.getByRole('button', { name: 'Stage fleet revision', exact: true }).click(); await completed(page);
    const fleetRevision = JSON.parse(await page.locator('#fleet-result').textContent()).revision;
    await page.getByLabel('Rollout request · JSON', { exact: true }).fill(JSON.stringify({ id:'browser-rollout',revision:fleetRevision,targets:['edge-a'],expected:{'edge-a':0},deadline:new Date(Date.now()+60000).toISOString() }));
    await accept(page, page.getByRole('button', { name: 'Create rollout', exact: true })); await completed(page);
    await accept(page, page.getByRole('button', { name: 'activate browser-rollout', exact: true })); await completed(page);
    await expect(page.locator('#targets')).toContainText('Desired ' + fleetRevision);
    const desired = await (await fetch(env.FLEET_ORIGIN + '/api/v1/fleet/desired', { headers:{Authorization:'Bearer synthetic-agent-token'} })).json();
    const ack = await fetch(env.FLEET_ORIGIN + '/api/v1/fleet/ack', { method:'POST',headers:{Authorization:'Bearer synthetic-agent-token','Content-Type':'application/json'},body:JSON.stringify({revision:desired.revision,generation:desired.generation}) }); assert.equal(ack.status,200);
    await page.getByRole('button', { name: 'Refresh status', exact: true }).click(); await completed(page);
    await expect(page.locator('#targets')).toContainText('Observed ' + fleetRevision);
    await accept(page, page.getByRole('button', { name: 'drain edge-a', exact: true })); await completed(page);
    await expect(page.locator('#targets')).toContainText('Desired drain: true; observed drain: false');
    await accept(page, page.getByRole('button', { name: 'revoke edge-a', exact: true })); await completed(page);
    await expect(page.locator('#targets')).toContainText('Desired revoke: true; observed revoke: false');
    await page.getByLabel('Tenant', { exact: true }).fill('tenant-b');
    await page.getByRole('button', { name: 'Load scoped fleet', exact: true }).click();
    await expect(page.getByRole('status')).toContainText('HTTP 403'); await expect(page.locator('#targets')).toBeEmpty();
  } finally { await s.close(); }
});

test('leases: real dry-run controller scope, list and exact revoke persist', async () => {
  const s = await session(env.LEASE_ORIGIN), { page } = s;
  try {
    await expect(page.locator('#capabilities')).toContainText('dry_run');
    await expect(page.locator('#lease-list')).toContainText('10.44.0.1/32');
    await accept(page, page.getByRole('button', { name: 'Revoke lease fixture-lease', exact: true })); await completed(page);
    await expect(page.locator('#lease-list')).toContainText('No active leases');
    const response = await fetch(env.LEASE_ORIGIN + '/v1/leases', { headers: { Authorization: 'Bearer ' + env.UI_TOKEN } });
    assert.deepEqual(await response.json(), []);
  } finally { await s.close(); }
});

test('usability: keyboard login, visible focus, 320px reflow, text contrast and input labels', async () => {
  const s = await session(env.UI_ORIGIN), { page } = s;
  try {
    await page.getByRole('button', { name: 'Log out', exact: true }).click();
    await page.getByLabel('Bearer token', { exact: true }).fill(env.UI_TOKEN);
    await page.keyboard.press('Tab'); await expect(page.getByRole('button', { name: 'Connect', exact: true })).toBeFocused();
    assert.equal(await page.getByRole('button', { name: 'Connect', exact: true }).evaluate(el => getComputedStyle(el).outlineWidth), '3px');
    await page.keyboard.press('Enter'); await expect(page.getByRole('button', { name: 'Refresh status', exact: true })).toBeFocused();
    const rollback = page.getByRole('button', { name: 'Roll back to selected', exact: true });
    await rollback.focus(); await page.keyboard.press('Enter');
    await expect(page.getByRole('button', { name: 'Cancel', exact: true })).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('status')).toHaveText('Operation cancelled.'); await expect(rollback).toBeFocused();
    await page.setViewportSize({ width: 320, height: 800 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    const unlabelled = await page.locator('input:visible,select:visible,textarea:visible').evaluateAll(elements => elements.filter(el => !el.labels?.length && !el.getAttribute('aria-label')).length);
    assert.equal(unlabelled, 0);
    const ratios = await page.evaluate(() => {
      const l = hex => { const c = hex.match(/\w\w/g).map(v => parseInt(v,16)/255).map(v => v <= .04045 ? v/12.92 : ((v+.055)/1.055)**2.4); return c[0]*.2126+c[1]*.7152+c[2]*.0722; };
      const ratio = (a,b) => (Math.max(l(a),l(b))+.05)/(Math.min(l(a),l(b))+.05);
      return { text:ratio('edf3f7','192630'), muted:ratio('bdcbd5','192630'), input:ratio('edf3f7','243541'), button:ratio('102522','8ad9d0'), border:ratio('8297a6','243541'), focus:ratio('8ad9d0','243541'), error:ratio('ffb9b9','101820') };
    });
    for (const [name, value] of Object.entries(ratios)) assert.ok(value >= (['border','focus'].includes(name) ? 3 : 4.5), `${name} contrast ${value}`);
    console.log('contrast ratios', ratios);
  } finally { await s.close(); }
});

test('auth: a late real API response cannot restore the workspace after logout', async () => {
  const s = await session(env.UI_ORIGIN), { page, context } = s;
  let release;
  const held = new Promise(resolve => { release = resolve; });
  let ready;
  const started = new Promise(resolve => { ready = resolve; });
  try {
    await context.route('**/api/v1/policy/revision', async route => {
      const response = await route.fetch(); ready(); await held; await route.fulfill({ response });
    });
    await page.getByRole('button', { name: 'Refresh status', exact: true }).click();
    await started;
    await page.getByRole('button', { name: 'Log out', exact: true }).click();
    const finished = page.waitForResponse(r => r.url() === env.UI_ORIGIN + '/api/v1/policy/revision');
    release(); await finished;
    await expect(page.getByRole('status')).toHaveText('Logged out. Token and workspace cleared.');
    await expect(page.locator('#workspace')).toBeHidden(); await expect(page.locator('#capabilities')).toBeEmpty();
    assert.equal(await page.locator('#bundle').inputValue(), '');
  } finally { release(); await s.close(); }
});
