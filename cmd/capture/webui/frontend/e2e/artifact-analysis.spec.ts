import { expect, test } from '@playwright/test';

for (const [state, outcome] of [['completed', 'matched'], ['completed', 'no-match'], ['completed', 'classified'], ['failed', ''], ['timed-out', ''], ['cancelled', ''], ['rejected', '']]) {
  test(`ui-mocked: artifact ${state}/${outcome} preserves coverage`, async ({ page, baseURL }) => {
    const unexpected: string[] = [], errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.context().route('**/*', async route => {
      const url = new URL(route.request().url());
      if (url.origin !== baseURL) { unexpected.push(url.href); return route.abort(); }
      if (!url.pathname.startsWith('/api/')) return route.continue();
      let json: unknown;
      switch (url.pathname) {
        case '/api/status': json = { activeInputFile: '/fixture.pcap', outputDir: '/fixture', isProcessing: false, isLiveMode: false }; break;
        case '/api/files/input': json = [{ path: '/fixture.pcap', name: 'fixture.pcap', isCompleted: true }]; break;
        case '/api/version': json = { version: 'ui-mocked' }; break;
        case '/api/menu-counts': json = {}; break;
        case '/api/alerts/stats': json = { totalAlerts: 0, groupCount: 0, bySeverity: {}, byRule: {}, recentAlerts: [], criticalAlerts: 0 }; break;
        case '/api/dbs/status': json = { satisfied: true, missing: [] }; break;
        case '/api/extracted-files': json = { files: [{ name: 'blob.bin', originalName: 'owned.bin', path: 'blob.bin', size: 5, modifiedTime: 1700000000, mimeType: 'application/octet-stream', sha256: 'owned-sha', hash: 'md5', isComplete: true, completenessReason: 'no-reported-loss' }], totalCount: 1, filesDir: '/fixture/files' }; break;
        case '/api/artifact-analysis': json = { version: 1, runId: 'owned', configDigest: 'config', state: state === 'completed' ? 'complete' : 'partial', rejected: state === 'rejected' ? 1 : 0,
          results: { 'owned-sha': { sha256: 'owned-sha', configDigest: 'config', analyzers: [{ engine: 'yara-x', state, outcome, digest: 'owned-rules', matches: outcome === 'matched' ? ['owned_fixture'] : [] }] } } }; break;
        default:
          if (url.pathname.startsWith('/api/extracted-files/download/')) return route.fulfill({ body: 'owned', contentType: 'application/octet-stream' });
          if (url.pathname.startsWith('/api/extracted-files/content/')) { json = { data: Buffer.from('owned').toString('base64'), offset: 0, size: 5, totalSize: 5, hasMore: false }; break; }
          unexpected.push(url.pathname); return route.abort();
      }
      return route.fulfill({ json });
    });
    await page.goto('/files');
    await page.getByRole('row').filter({ hasText: 'owned.bin' }).click();
    await expect(page.getByRole('dialog')).toBeVisible();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText(new RegExp(`yara-x: ${state}`))).toBeVisible();
    if (outcome) await expect(dialog.getByText(new RegExp(`yara-x: ${state}.*${outcome}`))).toBeVisible();
    if (state !== 'completed') await expect(dialog.getByText(/not a clean scan/)).toBeVisible();
    await expect(dialog.getByText('Artifact completeness: complete — no-reported-loss', { exact: true })).toBeVisible();
    expect(unexpected).toEqual([]); expect(errors).toEqual([]);
  });
}
