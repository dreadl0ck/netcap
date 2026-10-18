import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { chromium } from '@playwright/test';

export async function qualify(base, action, extraOrigins = []) {
  assert.equal(new URL(base).hostname, '127.0.0.1', 'owned loopback fixture required');
  for (const origin of extraOrigins) assert.equal(new URL(origin).hostname, '127.0.0.1', 'loopback packet fixture required');
  assert(process.env.NETCAP_BROWSER_OUTPUT, 'Go fixture output identity required');
  assert(process.env.NETCAP_BROWSER_EVIDENCE, 'private evidence directory required');
  const evidence = process.env.NETCAP_BROWSER_EVIDENCE;
  mkdirSync(evidence, { recursive: true });
  const failures = [];
  const revision = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  let browser, context, page;
  try {
    const response = await fetch(`${base}/api/status`, { redirect: 'error', signal: AbortSignal.timeout(5000) });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).outputDir, process.env.NETCAP_BROWSER_OUTPUT, 'unknown fixture server');
    browser = await chromium.launch({ headless: true, ...(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {}) });
    context = await browser.newContext({ viewport: { width: 1800, height: 1000 }, serviceWorkers: 'block' });
    await context.tracing.start({ screenshots: true, snapshots: true });
    await context.routeWebSocket('**/*', socket => {
      failures.push(`unexpected WebSocket: ${new URL(socket.url()).origin}`);
      socket.close();
    });
    const allowed = [new URL(base).origin, ...extraOrigins.map(url => new URL(url).origin)];
    await context.route('**/*', route => {
      const url = new URL(route.request().url());
      if (['http:', 'https:'].includes(url.protocol) && !allowed.includes(url.origin)) {
        failures.push(`unexpected origin: ${url.origin}${url.pathname}`);
        return route.abort();
      }
      return route.continue();
    });
    page = await context.newPage();
    page.on('pageerror', error => failures.push(error.message));
    page.on('response', response => {
      if (response.status() >= 500) failures.push(`${response.status()} ${new URL(response.url()).pathname}`);
    });
    const observations = await action(page);
    assert.deepEqual(failures, []);
    await context.tracing.stop();
    writeFileSync(path.join(evidence, 'report.json'), JSON.stringify({ passed: true, revision, executionClass: 'integration-local',
      outputDir: process.env.NETCAP_BROWSER_OUTPUT, browser: browser.version(), observations, failures }));
  } catch (error) {
    if (page) await page.screenshot({ path: path.join(evidence, 'failure.png'), fullPage: true }).catch(() => {});
    if (context) await context.tracing.stop({ path: path.join(evidence, 'trace.zip') }).catch(() => {});
    writeFileSync(path.join(evidence, 'report.json'), JSON.stringify({ passed: false, revision, error: String(error), failures }));
    throw error;
  } finally { await browser?.close(); }
}
