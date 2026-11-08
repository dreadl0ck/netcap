import { expect, test } from '@playwright/test';

for (const available of [true, false]) {
  test(`ui-mocked: host identity ${available ? 'keeps competing scope evidence' : 'stays unavailable on legacy captures'}`, async ({ page, baseURL }) => {
    const unexpected: string[] = [], errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.context().route('**/*', async route => {
      const url = new URL(route.request().url());
      if (url.origin !== baseURL) { unexpected.push(url.href); return route.abort(); }
      if (!url.pathname.startsWith('/api/')) return route.continue();
      let json: unknown;
      switch (url.pathname) {
        case '/api/status': json = { activeInputFile: '/owned.pcap', outputDir: '/owned', isProcessing: false }; break;
        case '/api/files/input': json = [{ path: '/owned.pcap', name: 'owned.pcap', isCompleted: true }]; break;
        case '/api/version': json = { version: 'ui-mocked' }; break;
        case '/api/menu-counts': json = {}; break;
        case '/api/alerts/stats': json = { totalAlerts: 0, groupCount: 0, bySeverity: {}, byRule: {}, recentAlerts: [] }; break;
        case '/api/dbs/status': json = { satisfied: true, missing: [] }; break;
        case '/api/behavior/asset':
          expect(url.searchParams.get('asset')).toBe('192.0.2.1');
          json = { asset: '192.0.2.1', records: [], totalRecords: 0, truncated: false }; break;
        case '/api/hosts': json = { totalCount: 1, hosts: [{ addr: '192.0.2.1', numPackets: 3, bytes: 240, isInternal: false,
          dnsNames: [], applications: [], topProtocols: [], topSrcPorts: [], topDstPorts: [], topContactedPorts: [],
          protocolsCount: 0, snisCount: 0, srcPortsCount: 0, dstPortsCount: 0, contactedPortsCount: 0,
          timestampFirst: 1700000000000000000, timestampLast: 1700000000000000000 }],
          ...(available ? { identity: { state: 'available', report: { schema: 1, overflow: 1, unscopedRecords: 2, limitations: ['Capture-scoped evidence'], hosts: [
            { ip: '192.0.2.1', scope: 'vlan-1', hostnameState: 'ambiguous', macState: 'ambiguous', evidence: [], bindings: [], accounts: [{ name: 'analyst-fixture', at: '1700000000000000001', fullNameState: 'unknown' }] },
            { ip: '192.0.2.1', scope: 'vlan-2', hostname: 'printer-fixture', hostnameState: 'observed', macState: 'unknown', evidence: [], bindings: [], accounts: [] },
          ] } } } : {}),
        }; break;
        default:
          if (['top-talkers', 'traffic-distribution', 'applications', 'protocols'].some(name => url.pathname === `/api/hosts/${name}`)) return route.fulfill({ contentType: 'text/html', body: '<html><body>ui-mocked chart</body></html>' });
          unexpected.push(url.pathname); return route.abort();
      }
      return route.fulfill({ json });
    });
    await page.goto('/hosts');
    await page.getByRole('row').filter({ hasText: '192.0.2.1' }).first().click();
    if (available) {
      await expect(page.getByText('Scope: vlan-1')).toBeVisible();
      await expect(page.getByText('Scope: vlan-2')).toBeVisible();
      await expect(page.getByText(/Hostname: unavailable \(ambiguous\)/)).toBeVisible();
      await page.getByText('Names, account evidence and link bindings (times in Unix ns)', { exact: true }).first().click();
      await expect(page.getByText(/1700000000000000001/)).toBeVisible();
      await expect(page.getByText(/Omitted observations: 1; unscoped records: 2/)).toBeVisible();
    } else {
      await expect(page.getByText('Identity evidence unavailable for this capture.')).toBeVisible();
    }
    expect(unexpected).toEqual([]); expect(errors).toEqual([]);
  });
}

test('ui-mocked: failed capture downloads metadata for its own identity without selecting the active row', async ({ page, baseURL }) => {
  const unexpected: string[] = [], errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.context().route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin !== baseURL) { unexpected.push(url.href); return route.abort(); }
    if (!url.pathname.startsWith('/api/')) return route.continue();
    let json: unknown;
    switch (url.pathname) {
      case '/api/status': json = { activeInputFile: '/other.pcap', outputDir: '/other', isProcessing: false }; break;
      case '/api/files/input': json = [{ id: 'failed-owned', path: '/failed.pcap', name: 'failed.pcap', size: 4096, modifiedTime: 1700000000, isCompleted: false, error: 'Owned synthetic failure' }]; break;
      case '/api/version': json = { version: 'ui-mocked' }; break;
      case '/api/menu-counts': json = {}; break;
      case '/api/alerts/stats': json = { totalAlerts: 0, groupCount: 0, bySeverity: {}, byRule: {}, recentAlerts: [] }; break;
      case '/api/dbs/status': json = { satisfied: true, missing: [] }; break;
      case '/api/investigation/reproduction':
        expect(Object.fromEntries(url.searchParams)).toEqual({ sessionId: 'failed-owned' });
        json = { schema: 'netcap-reproduction-metadata/v1', state: 'metadata-only', captureStatus: 'error', attachments: [{ name: 'logs-and-payloads', state: 'omitted-sensitive' }] }; break;
      default: unexpected.push(url.pathname); return route.abort();
    }
    return route.fulfill({ json });
  });
  await page.goto('/pcaps');
  const pending = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download reproduction metadata', exact: true }).click();
  const download = await pending;
  expect(download.suggestedFilename()).toBe('netcap-reproduction-metadata.json');
  const stream = await download.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  const bundle = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  expect(bundle.state).toBe('metadata-only');
  expect(bundle.captureStatus).toBe('error');
  expect(bundle.attachments).toEqual([{ name: 'logs-and-payloads', state: 'omitted-sensitive' }]);
  await expect(page).toHaveURL(/\/pcaps$/);
  expect(unexpected).toEqual([]); expect(errors).toEqual([]);
});
