import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium, expect } from '@playwright/test';

const [, , base, workdir, fixtures] = process.argv;
assert.match(base, /^http:\/\/127\.0\.0\.1:\d+$/);
const [a, b] = Object.values(JSON.parse(fixtures)).sort((x, y) => x.name.localeCompare(y.name));
assert(a?.sessionId && b?.sessionId && a.sessionId !== b.sessionId && a.coverage, 'need two completed, distinct preloads, one partial');
const scoped = (path, capture = a) => `${path}?sessionId=${encodeURIComponent(capture.sessionId)}`;
const check = expect.configure({ timeout: 5000 });
const warning = /Partial packet coverage:|UDP stream retention limit:/;
const launch = process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : { channel: 'chrome' };
const browser = await chromium.launch({ ...launch, args: ['--disable-background-networking'] });
const failed = [];
let passed = 0;

async function run(name, action) {
  const context = await browser.newContext({ baseURL: base, locale: 'en-US', viewport: { width: 1600, height: 1000 }, serviceWorkers: 'block' });
  await context.tracing.start({ screenshots: true, snapshots: true });
  const errors = new Set();
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    if (url.origin === base) return route.continue();
    errors.add(`unexpected request: ${url.origin}${url.pathname}`);
    return route.abort();
  });
  await context.routeWebSocket('**/*', socket => { errors.add(`unexpected WebSocket: ${socket.url()}`); socket.close(); });
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  page.on('pageerror', error => {
    // Playwright tries to block service workers even in opaque-origin chart frames.
    if (!/sandboxed and lacks the 'allow-same-origin'/.test(error.message)) errors.add(error.message);
  });
  page.on('response', response => {
    if (response.status() >= 500) errors.add(`${response.status()} ${new URL(response.url()).pathname}`);
  });
  const filename = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  try {
    await action(page, context);
    assert.deepEqual([...errors], []);
    await context.tracing.stop();
    console.log(`PASS ${name}`);
    passed++;
  } catch (error) {
    await page.screenshot({ path: join(workdir, `${filename}.png`) }).catch(() => {});
    await context.tracing.stop({ path: join(workdir, `${filename}.zip`) }).catch(() => {});
    console.error(`FAIL ${name}: ${error.message}`, [...errors]);
    failed.push(name);
  } finally {
    await context.close();
  }
}

async function start(page, path) {
  await page.goto(path);
  await page.getByRole('button', { name: 'Start exploring' }).click();
}

async function json(request, path) {
  const response = await request.get(path, { maxRedirects: 0 });
  assert.equal(response.status(), 200, path);
  return response.json();
}

async function overviewCount(page, expected) {
  const total = page.getByText('Total Records', { exact: true });
  await check(total.locator('..').getByRole('heading')).toHaveText(expected.toLocaleString('en-US'));
}

async function snapshot(page, name) {
  if (process.env.NETCAP_TRY_SCREENSHOTS === '1') await page.screenshot({ path: join(workdir, `${name}.png`) });
}

const inventories = [
  ['hosts', 'Hosts', /192\.0\.2\.11/],
  ['devices', 'Devices', /02:00:00:00:00:0b/i],
  ['connections', 'Connections', /192\.0\.2\.11/],
  ['http', 'HTTP', /sample-a\.test|sample-a\.txt/],
  ['services', 'Services', /198\.51\.100\.11/],
];

try {
  const identity = await requestIdentity();
  assert(identity.isServiceMode, 'must exercise the embedded service-mode UI');
  await run('Fresh landing aggregates completed captures', async page => {
    const [left, right] = await Promise.all([a, b].map(capture => json(page.request, scoped('/api/audit-stats', capture))));
    assert(left.totalRecords > 0 && right.totalRecords > 0);
    const chart = page.waitForResponse(response => new URL(response.url()).pathname === '/api/visualize/geo-all').catch(() => undefined);
    await start(page, '/');
    await check(page.getByRole('combobox', { name: 'Scope' })).toContainText('All PCAPs');
    await overviewCount(page, left.totalRecords + right.totalRecords);
    const response = await chart;
    assert(response, 'aggregate chart did not load');
    assert.equal(response.status(), 200);
    const url = new URL(response.url());
    assert.equal(url.searchParams.get('scope'), 'all');
    assert.equal(url.searchParams.has('sessionId'), false);
    await check(page.frameLocator('iframe[title="Global Geolocation Chart"]').locator('canvas').first()).toBeVisible();
    await snapshot(page, 'traffic-overview');
  });

  await run('Dashboard scope follows the capture URL and returns to All PCAPs', async page => {
    await page.addInitScript(() => { if (window === window.top) sessionStorage.setItem('dashboard-pcap-scope', 'current'); });
    const [left, right] = await Promise.all([a, b].map(capture => json(page.request, scoped('/api/audit-stats', capture))));
    await start(page, '/');
    await overviewCount(page, left.totalRecords + right.totalRecords);
    const scope = page.getByRole('combobox', { name: 'Scope' });
    await scope.click();
    await page.getByRole('option', { name: b.name, exact: true }).click();
    await check(page).toHaveURL(scoped('/', b));
    await check(scope).toContainText(b.name);
    await overviewCount(page, right.totalRecords);
    await page.reload();
    await overviewCount(page, right.totalRecords);
    await scope.click();
    await page.getByRole('option', { name: /All PCAPs/ }).click();
    await check(page).toHaveURL('/');
    await overviewCount(page, left.totalRecords + right.totalRecords);
  });

  for (const [path, label, cell] of inventories) {
    await run(`${label} shows selected capture records via navigation`, async page => {
      await start(page, `/view/${a.sessionId}`);
      await page.getByRole('button', { name: 'Data', exact: true }).click();
      await page.getByRole('link').filter({ hasText: new RegExp(`^\\d*${label}$`) }).click();
      await check(page).toHaveURL(scoped(`/${path}`));
      await check(page.getByRole('cell', { name: cell }).first()).toBeVisible();
    });
  }

  await run('Direct inventory link selects a sample and switching survives reload', async page => {
    await start(page, '/hosts');
    await check(page).toHaveURL(scoped('/hosts'));
    await check(page.getByRole('cell', { name: '192.0.2.11', exact: true })).toBeVisible();
    await page.getByRole('banner').getByRole('combobox').click();
    await page.getByRole('option').filter({ hasText: b.name }).click();
    await check(page).toHaveURL(scoped('/hosts', b));
    await check(page.getByRole('cell', { name: '192.0.2.12', exact: true })).toBeVisible();
    await check(page.getByRole('cell', { name: '192.0.2.11', exact: true })).toHaveCount(0);
    await page.reload();
    await check(page.getByRole('cell', { name: '192.0.2.12', exact: true })).toBeVisible();
  });

  for (const path of ['/records', '/audit']) {
    await run(`${path} has one capture selector and no coverage banner`, async page => {
      await start(page, scoped(path));
      await check(page.getByRole('main').getByText(/^HTTP$/).first()).toBeVisible();
      await check(page.getByRole('banner').getByRole('combobox')).toContainText(a.name);
      await check(page.getByRole('combobox')).toHaveCount(1);
      await check(page.getByText(warning)).toHaveCount(0);
      if (path === '/records') await snapshot(page, 'records');
    });
  }

  await run('Alerts list omits coverage panel', async page => {
    await start(page, scoped('/alerts'));
    await check(page.getByRole('main').getByText(/Total Alerts|No alerts/i).first()).toBeVisible();
    await check(page.getByText('Network detection coverage', { exact: true })).toHaveCount(0);
    await check(page.getByText(warning)).toHaveCount(0);
    await snapshot(page, 'alerts');
  });

  await run('Files list omits pipeline diagnostics and opens extracted content', async page => {
    await start(page, scoped('/files'));
    const row = page.getByRole('row').filter({ hasText: 'sample-a.txt' });
    await check(row).toBeVisible();
    await check(page.getByText(/Artifact processing:|Extraction issues|yara-x: ready|magika: ready/)).toHaveCount(0);
    await check(page.getByText(warning)).toHaveCount(0);
    await snapshot(page, 'files');
    await row.click();
    await check(page.getByRole('dialog').getByText(/Synthetic Netcap fixture for sample-a/)).toBeVisible();
  });

  await run('Aggregate and capture data exclude another visitor’s upload', async (page, context) => {
    const privateName = 'private-fixture.pcap';
    const before = await json(page.request, '/api/audit-stats?scope=all');
    const owner = await browser.newContext({ baseURL: base });
    try {
      const buffer = await readFile(join(workdir, b.name));
      const upload = await owner.request.post('/api/upload', { multipart: { file: { name: privateName, mimeType: 'application/octet-stream', buffer } } });
      assert(upload.ok(), `fixture upload returned ${upload.status()}`);
      const { sessionId } = await upload.json();
      assert(sessionId);
      await check.poll(async () => (await json(owner.request, `/api/status/${sessionId}`)).status).toBe('completed');
      const own = await json(owner.request, '/api/audit-stats?scope=all');
      assert(own.totalRecords > before.totalRecords, 'owner aggregate should include its finished upload');
      assert.equal((await context.request.get(`/api/hosts?sessionId=${sessionId}`)).status(), 403);
      assert.equal((await json(page.request, '/api/audit-stats?scope=all')).totalRecords, before.totalRecords);
      await start(page, '/');
      await overviewCount(page, before.totalRecords);
      await page.getByRole('combobox', { name: 'Scope' }).click();
      await check(page.getByRole('option').filter({ hasText: privateName })).toHaveCount(0);
    } finally {
      await owner.close();
    }
  });
} finally {
  await browser.close();
}
console.log(JSON.stringify({ executionClass: 'integration-local', browser: browser.version(), passed, failed, evidence: workdir }));
assert.equal(failed.length, 0, failed.join(', '));

async function requestIdentity() {
  const visitor = await browser.newContext({ baseURL: base });
  try {
    const files = await json(visitor.request, '/api/files/input');
    for (const expected of [a, b]) {
      assert(files.some(row => row.name === expected.name && row.sessionId === expected.sessionId && row.isCompleted), 'wrong fixture server');
    }
    const partial = await json(visitor.request, scoped('/api/status'));
    assert(partial.coverage && partial.udpOmittedStreams === 2, 'fixture must carry the removed diagnostics');
    return await json(visitor.request, '/api/status');
  } finally {
    await visitor.close();
  }
}
