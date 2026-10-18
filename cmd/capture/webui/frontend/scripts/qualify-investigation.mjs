import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { expect } from '@playwright/test';
import { qualify } from './browser-fixture.mjs';

const [base, stream, inputHash] = process.argv.slice(2);
await qualify(base, async page => {
  await page.goto(`${base}/investigation-evidence`);
  await expect(page.getByText(`Input SHA-256: ${inputHash}`, { exact: true })).toBeVisible();
  await expect(page.getByText('Status: completed · Ingress: 1 · Admitted: 1 · Queue drops: 0 · Truncated: 0', { exact: true })).toBeVisible();
  await expect(page.getByText('Kernel received: unavailable · Kernel drops: unavailable', { exact: true })).toBeVisible();
  const expected = Buffer.from([0, 255, 27, 60, 115, 62, 13, 10, 128]);
  const download = async direction => {
    const [artifact] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: `Download ${direction}`, exact: true }).click()]);
    assert.equal(await artifact.failure(), null);
    assert.equal(artifact.suggestedFilename(), `${stream}-${direction}.${direction === 'manifest' ? 'json' : 'bin'}`);
    return readFile(await artifact.path());
  };
  assert.deepEqual(await download('client'), expected);
  assert.deepEqual(await download('server'), Buffer.alloc(0));
  const manifestBytes = await download('manifest');
  const manifest = JSON.parse(manifestBytes);
  assert.equal(manifest.client.sha256, createHash('sha256').update(expected).digest('hex'));
  assert.equal(manifest.client.length, String(expected.length));
  assert.equal(manifest.server.length, '0');
  assert.equal(manifest.connectionKey, 'synthetic-pcap');
  assert.equal(manifest.spans.length, 1);
  assert.ok(manifest.limitations.includes('stream completeness and packet provenance require the original capture'));
  await page.reload();
  await expect(page.getByText(`Input SHA-256: ${inputHash}`, { exact: true })).toBeVisible();
  assert.deepEqual(await download('client'), expected);
  assert.deepEqual(await download('manifest'), manifestBytes);
  // Missing record index must remain an error, never a successful zero-match report.
  const queryResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/api/flows/query');
  await page.getByRole('button', { name: 'Run scoped query', exact: true }).click();
  assert.equal((await queryResponse).status(), 404);
  await expect(page.getByRole('alert').filter({ hasText: 'Flow query unavailable:' })).toBeVisible();
  await expect(page.getByText(/^Matched \d+ observations/)).toHaveCount(0);
  const select = async name => {
    await page.getByRole('combobox').first().click();
    await page.getByRole('option', { name: new RegExp(name) }).click();
  };
  await select('empty.pcap');
  await expect(page.getByText('No saved stream artifacts in this analysis.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Download client', exact: true })).toHaveCount(0);
  await expect(page.getByRole('alert').filter({ hasText: 'Capture provenance unavailable:' })).toBeVisible();
  await select('unavailable.pcap');
  await expect(page.getByRole('alert').filter({ hasText: 'Stream evidence unavailable' })).toBeVisible();
  await expect(page.getByText('No saved stream artifacts in this analysis.', { exact: true })).toHaveCount(0);
  await select('selected.pcap');
  await expect(page.getByText(`Input SHA-256: ${inputHash}`, { exact: true })).toBeVisible();
  assert.deepEqual(await download('client'), expected);
  return { checks: 8, inputHash, payloadBytes: expected.length, persistence: 'reload and capture switch', missingIndex: 404,
    emptyDistinctFromUnavailable: true, boundary: 'PCAP reader → persistence writers → HTTP → production React; no collector/reassembly claim' };
});
