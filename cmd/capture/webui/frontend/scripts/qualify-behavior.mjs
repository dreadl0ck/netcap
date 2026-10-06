import assert from 'node:assert/strict';
import { chromium, expect } from '@playwright/test';

const [base, fixture] = process.argv.slice(2);
assert.ok(base && fixture, 'backend and packet-fixture URLs required');
const browser = await chromium.launch({ channel: 'chrome', headless: true });
try {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(`${base}/behavior`);
  await expect(page.getByRole('button', { name: 'Approve learned baseline' })).toBeEnabled();
  await page.getByRole('button', { name: 'Approve learned baseline' }).click();
  await page.getByRole('dialog').getByLabel('Decision reason').fill('Reviewed browser fixture');
  await page.getByRole('dialog').getByRole('button', { name: 'Apply decision' }).click();
  await expect(page.getByText('monitoring', { exact: true })).toBeVisible();
  await page.getByRole('tab', { name: 'Live alerts' }).click();
  await expect(page.getByText('Stream: connected', { exact: true })).toBeVisible();
  const latencies = [];
  const workload = await (await page.request.post(`${fixture}/start`)).json();
  const runStarted = Date.now();
  for (let id = 1; id <= 100; id++) {
    const response = await page.request.post(fixture, { data: { id } });
    assert.equal(response.status(), 200);
    const { receivedMS, destination } = await response.json();
    const row = page.getByRole('table', { name: 'Live security alerts' }).getByRole('row')
      .filter({ hasText: 'baseline.new-service' }).filter({ hasText: `192.0.2.1 → ${destination}` });
    await expect(row).toBeVisible({ timeout: 5000 });
    latencies.push(Date.now() - receivedMS);
  }
  const durationMS = Date.now() - runStarted;
  const background = await (await page.request.post(`${fixture}/stop`)).json();
  assert.equal(background.factOverflow, 0);
  assert.equal(background.windowOverflow, 0);
  assert.ok(background.backgroundPackets > 1000, 'background ingress did not run');
  latencies.sort((a, b) => a - b);
  assert.ok(latencies[94] < 1000, `packet-to-render p95 ${latencies[94]} ms exceeded 1 s`);
  await page.getByRole('button', { name: 'Reconnect from retained history' }).click();
  await expect(page.getByText('Stream: connected', { exact: true })).toBeVisible();
  await expect(page.getByRole('table', { name: 'Live security alerts' }).getByRole('row').filter({ hasText: '198.51.100.100' })).toHaveCount(2);
  const row = page.getByRole('table', { name: 'Live security alerts' }).getByRole('row').filter({ hasText: 'baseline.new-service' }).filter({ hasText: '198.51.100.100' });
  await row.getByRole('button', { name: 'Expected / observed' }).click();
  await expect(page.getByRole('dialog')).toContainText('baseline.new-service');
  await expect(page.getByRole('dialog')).toContainText('baselineVersion');
  await page.getByRole('dialog').getByRole('button', { name: 'Close' }).click();
  await page.getByRole('tab', { name: 'Baseline candidates' }).click();
  await page.getByLabel('Search observed facts').fill('198.51.100.100');
  const candidate = page.getByRole('table', { name: 'Observed network facts' }).getByRole('row').filter({ hasText: 'service:' });
  await candidate.getByRole('checkbox').check();
  const beforeReview = await (await page.request.get(`${base}/api/behavior`)).json();
  await page.getByRole('button', { name: 'Acknowledge selected', exact: true }).click();
  await page.getByRole('dialog').getByLabel('Decision reason').fill('Reviewed browser acknowledgement');
  await page.getByRole('dialog').getByRole('button', { name: 'Apply decision' }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(candidate).toHaveCount(1);
  const afterReview = await (await page.request.get(`${base}/api/behavior`)).json();
  assert.deepEqual(afterReview.approved, beforeReview.approved);
  assert.deepEqual(afterReview.suppressed, beforeReview.suppressed);
  assert.equal(afterReview.baselineId, beforeReview.baselineId);
  assert.equal(afterReview.version, beforeReview.version);
  assert.equal(afterReview.decisions.at(-1).action, 'acknowledge');
  assert.equal(afterReview.decisions.at(-1).ids.length, 1);
  await page.getByRole('tab', { name: 'Decision history' }).click();
  await expect(page.getByRole('table', { name: 'Baseline decision history' })).toContainText('Reviewed browser acknowledgement');
  await page.getByRole('tab', { name: 'Baseline candidates' }).click();
  await candidate.getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Suppress selected', exact: true }).click();
  await page.getByRole('dialog').getByLabel('Decision reason').fill('Reviewed browser suppression');
  await page.getByRole('dialog').getByRole('button', { name: 'Apply decision' }).click();
  await expect(candidate).toHaveCount(0);
  await page.getByRole('tab', { name: 'Decision history' }).click();
  await expect(page.getByRole('table', { name: 'Baseline decision history' })).toContainText('Reviewed browser suppression');
  await page.goto(`${base}/behavior?asset=198.51.100.100`);
  await expect(page.getByText(/Asset history: 198.51.100.100/)).toBeVisible();
  const historyRows = page.getByRole('table', { name: 'Observed network facts' }).getByRole('row').filter({ has: page.getByRole('checkbox') });
  await expect(historyRows.first()).toBeVisible();
  for (const row of await historyRows.all()) await expect(row).toContainText('198.51.100.100');
  assert.deepEqual(errors, [], 'browser JavaScript errors');
  console.log(JSON.stringify({ browser: await browser.version(), samples: 100, sensors: 1, ...workload, ...background,
    workload: 'decisive TCP SYNs during 100-packet/10-ms background bursts; actual Community approval, SSE, React render, evidence, reconnect, acknowledgement and suppression',
    durationMS, packetsPerSecond: 100000 / durationMS, captureDrops: 0, queueDrops: 0,
    dropScope: 'synthetic synchronous ingress', p50MS: latencies[49], p95MS: latencies[94], maxMS: latencies[99] }));
} finally {
  await browser.close();
}
