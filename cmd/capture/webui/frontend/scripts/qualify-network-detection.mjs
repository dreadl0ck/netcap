import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';

const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1800, height: 1000 } });
  const errors = [];
  page.on('pageerror', error => errors.push(String(error)));
  await page.goto(`${process.argv[2]}/alerts`);
  await page.getByText('Network detection coverage', { exact: true }).waitFor();
  await page.getByText(/5 configured indicators/).waitFor();
  const grouped = await (await page.request.get(`${process.argv[2]}/api/alerts/grouped`)).json();
  assert.ok(grouped.groups.length > 0, JSON.stringify(grouped));
  await page.getByText('intel.c2', { exact: true }).first().click();
  await page.getByRole('button', { name: 'View Sample 1', exact: true }).click();
  await page.getByRole('heading', { name: 'Why this finding fired' }).waitFor();
  await page.getByText('Indicator match', { exact: true }).waitFor();
  await page.getByText('Indicator provenance', { exact: true }).waitFor();
  await page.getByText('Indicator association does not establish execution or compromise', { exact: true }).waitFor();
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export original evidence JSON' }).click()]);
  assert.equal(download.suggestedFilename(), 'netcap-detection-evidence.json');
  assert.equal(errors.length, 0, errors.join('\n'));
  console.log('Real API → coverage → classified finding → provenance/limits → evidence download passed');
} finally { await browser.close(); }
