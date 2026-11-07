import { expect, test } from '@playwright/test';

test('ui-mocked: create a source-bound subset child and return to its parent', async ({ page, baseURL }) => {
  const unexpected: string[] = [], errors: string[] = [];
  const parent = { id: 'parent-content', path: '/owned.pcap', name: 'owned.pcap', size: 4096, modifiedTime: 1700000000, isCompleted: true };
  const child = { ...parent, id: 'analysis-child', path: '/analysis-child/source/selected.pcapng', name: 'selected.pcapng', parentInputFile: parent.path,
    analysisSelector: 'packet-subset', packetSelection: { version: 1, sourceSHA256: 'a'.repeat(64), bpf: 'tcp port 9243', startNs: '1700000000000000001', endNs: '1700000000000000002' } };
  const files = [parent];
  let active = parent.path;
  let submitted: unknown;
  page.on('pageerror', error => errors.push(error.message));
  await page.context().route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== baseURL) { unexpected.push(url.href); return route.abort(); }
    if (!url.pathname.startsWith('/api/')) return route.continue();
    let json: unknown;
    switch (url.pathname) {
      case '/api/status': json = { activeInputFile: active, outputDir: '/owned', isProcessing: false, childAnalysisVersion: 1, inputFiles: files.map(f => f.path), isMultiFile: files.length > 1 }; break;
      case '/api/files/input': json = files; break;
      case '/api/version': json = { version: 'ui-mocked' }; break;
      case '/api/menu-counts': json = {}; break;
      case '/api/alerts/stats': json = { totalAlerts: 0, groupCount: 0, bySeverity: {}, byRule: {}, recentAlerts: [] }; break;
      case '/api/dbs/status': json = { satisfied: true, missing: [] }; break;
      case '/api/investigation/capture':
        expect(url.searchParams.get('inputFile')).toBe(parent.path);
        json = { runId: 'parent-generation', inputSHA256: 'a'.repeat(64) }; break;
      case '/api/reanalyze':
        expect(request.method()).toBe('POST');
        submitted = request.postDataJSON(); files.push(child);
        json = { success: true, sessionId: child.id, path: child.path }; break;
      case '/api/set-directory':
        expect(request.method()).toBe('POST');
        expect(request.postDataJSON()).toEqual({ inputFile: parent.path }); active = parent.path;
        json = { success: true, outputDir: '/owned', activeInputFile: active }; break;
      default: unexpected.push(url.pathname); return route.abort();
    }
    return route.fulfill({ json });
  });
  await page.goto('/pcaps');
  await page.getByRole('button', { name: 'Create child analysis for owned.pcap', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('combobox', { name: 'Analysis scope' }).click();
  await page.getByRole('option', { name: 'Selected packets' }).click();
  await dialog.getByLabel('Packet selection BPF').fill('tcp port 9243');
  await dialog.getByLabel('Start time (inclusive nanoseconds)').fill('1700000000000000001');
  await dialog.getByLabel('End time (inclusive nanoseconds)').fill('1700000000000000002');
  await dialog.getByRole('button', { name: 'Reanalyze', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(submitted).toEqual({ inputFile: parent.path, runId: 'parent-generation', selection: {
    version: 1, sourceSHA256: 'a'.repeat(64), bpf: 'tcp port 9243', startNs: '1700000000000000001', endNs: '1700000000000000002',
  } });
  const childRow = page.getByRole('row').filter({ hasText: 'selected.pcapng (child analysis)' });
  await expect(childRow).toBeVisible();
  await expect(childRow.getByText('Selected packets: tcp port 9243; 1700000000000000001–1700000000000000002 ns', { exact: true })).toBeVisible();
  await expect(page.getByRole('row').filter({ hasText: 'owned.pcap' })).toBeVisible();
  const selected = page.waitForRequest(r => new URL(r.url()).pathname === '/api/set-directory');
  await childRow.getByRole('button', { name: 'Parent', exact: true }).click();
  await selected;
  await expect(childRow).toBeVisible();
  expect(unexpected).toEqual([]); expect(errors).toEqual([]);
});
