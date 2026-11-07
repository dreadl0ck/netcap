import { expect, test } from '@playwright/test';

for (const mode of ['capture-time', 'legacy', 'unavailable']) {
  test(`ui-mocked: certificate ${mode} evidence remains qualified`, async ({ page, baseURL }) => {
    const errors: string[] = [], unexpected: string[] = [];
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
        case '/api/certificates': json = { totalCount: 1, certificates: [{ timestamp: 1590969600000000000, srcIP: '192.0.2.1', dstIP: '192.0.2.2', srcPort: 1234, dstPort: 443,
          subjectCommonName: 'owned.example.test', issuerCommonName: 'owned.example.test', subjectAltNames: [], keyUsage: [], extKeyUsage: [], sha256Fingerprint: 'owned-fingerprint',
          communityId: '1:owned', communityIds: ['1:owned'], seenCount: 1, firstSeen: 1590969600000000000, lastSeen: 1590969600000000000, daysUntilExpiration: 100, isExpired: false, isSelfSigned: false, publicKeySize: 256,
          ...(mode === 'legacy' ? {} : { assessmentBasis: mode, validityState: mode === 'capture-time' ? 'valid' : 'unavailable', assessmentTimeNs: '1590969600000000123', certificateSender: 'client', selfSignatureState: 'verified', notBeforeRFC3339: '2020-01-01T00:00:00Z', notAfterRFC3339: '9999-12-31T00:00:00Z' }),
        }] }; break;
        default:
          if (url.pathname.startsWith('/api/certificates/')) return route.fulfill({ contentType: 'text/html', body: '<html><body>ui-mocked chart</body></html>' });
          unexpected.push(url.pathname); return route.abort();
      }
      return route.fulfill({ json });
    });
    await page.goto('/certificates');
    await page.getByRole('row').filter({ hasText: 'owned.example.test' }).first().click();
    if (mode === 'capture-time') {
      await expect(page.getByText(/1590969600000000123 ns/)).toBeVisible();
      await expect(page.getByText(/sender: client/)).toBeVisible();
      await expect(page.getByText(/Not After: 9999-12-31T00:00:00Z/)).toBeVisible();
    } else {
      await expect(page.getByText(/false flags do not establish validity/)).toBeVisible();
      await expect(page.getByText('Valid for 100 days', { exact: true })).toHaveCount(0);
    }
    expect(unexpected).toEqual([]); expect(errors).toEqual([]);
  });
}

test('ui-mocked: HTTP packet export carries observed nonstandard ports', async ({ page, baseURL }) => {
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
      case '/api/secrets': json = { secrets: [], totalCount: 0 }; break;
      case '/api/http': json = { http: [{ timestamp: 1590969600000000000, proto: 'HTTP/1.1', method: 'GET', url: '/owned', host: 'owned.example.test', srcIP: '192.0.2.1', dstIP: '198.51.100.1', srcPort: 52123, dstPort: 9243, statusCode: 200, requestHeader: {}, responseHeader: {}, parameters: {} }], totalCount: 1 }; break;
      case '/api/http/download-pcap': return route.fulfill({ contentType: 'application/vnd.tcpdump.pcap', body: 'owned fixture bytes' });
      default:
        if (['top-hosts', 'status-codes', 'methods', 'content-types'].some(name => url.pathname === `/api/http/${name}`)) return route.fulfill({ contentType: 'text/html', body: '<html><body>owned chart</body></html>' });
        unexpected.push(url.pathname); return route.abort();
    }
    return route.fulfill({ json });
  });
  await page.goto('/http');
  await page.getByRole('row').filter({ hasText: 'owned.example.test' }).first().click();
  const request = page.waitForRequest(r => new URL(r.url()).pathname === '/api/http/download-pcap');
  await page.getByRole('button', { name: 'Download PCAP', exact: true }).click();
  expect(Object.fromEntries(new URL((await request).url()).searchParams)).toEqual({ srcIP: '192.0.2.1', dstIP: '198.51.100.1', srcPort: '52123', dstPort: '9243', protocol: 'TCP' });
  expect(unexpected).toEqual([]); expect(errors).toEqual([]);
});
