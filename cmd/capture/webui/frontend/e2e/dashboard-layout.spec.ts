import { expect, test } from '@playwright/test';

const chart = (id: string, auditType: string, x: number, y: number) => ({
  id, title: id, description: '', auditType, field: 'Field', chartType: 'pie', showLegend: true, maxDataPoints: 1000,
  layout: { x, y, w: 6, h: 4 },
});
const dashboard = {
  id: 'builtin-layout', name: 'Layout', description: '', gridCols: 12, rowHeight: 80, builtin: true,
  charts: [chart('Hosts', 'Host', 0, 0), chart('Vendors', 'DeviceProfile', 6, 0), chart('Files', 'File', 0, 4), chart('Software', 'Software', 6, 4)],
};

for (const width of [1000, 1280, 1440, 1920, 700]) {
  test(`ui-mocked: dashboard charts stay aligned and empty charts are hidden at ${width}px`, async ({ page, baseURL }) => {
    const errors: string[] = [];
    // Chart iframes are opaque-origin sandboxes, where the harness's own
    // service-worker blocking throws; only application errors count.
    page.on('pageerror', error => { if (!/sandboxed and lacks the 'allow-same-origin'/.test(error.message)) errors.push(error.message); });
    await page.setViewportSize({ width, height: 1100 });
    await page.addInitScript(() => { if (window.top === window) window.localStorage.setItem('dashboard-active-view', 'builtin-layout'); });
    await page.context().route('**/*', async route => {
      const url = new URL(route.request().url());
      if (url.origin !== baseURL) return route.abort();
      if (!url.pathname.startsWith('/api/')) return route.continue();
      switch (url.pathname) {
        case '/api/dashboards': return route.fulfill({ json: [dashboard] });
        case '/api/dashboards/builtin-layout': return route.fulfill({ json: dashboard });
        case '/api/files/audit': return route.fulfill({ json: ['Host', 'DeviceProfile', 'File', 'Software'].map(type => ({ type, name: `${type}.ncap.gz` })) });
        case '/api/chart/data':
          if (url.searchParams.get('type') === 'File') return route.fulfill({ status: 204, body: '' });
          if (url.searchParams.get('type') === 'Software') return route.fulfill({ status: 500, body: 'corrupt audit file' });
          return route.fulfill({ contentType: 'text/html', body: '<html><body>chart</body></html>' });
        case '/api/status': return route.fulfill({ json: { activeInputFile: '/owned.pcap', outputDir: '/owned', isProcessing: false } });
        case '/api/files/input': return route.fulfill({ json: [] });
        default: return route.fulfill({ json: {} });
      }
    });
    await page.goto('/');
    const view = page.getByRole('tab', { name: 'Layout' });
    if (await view.count()) await view.click();
    const tile = (name: string) => page.locator('.react-grid-item').filter({ hasText: name });
    await expect(tile('Hosts')).toBeVisible();
    await expect(page.getByText('Failed to render chart')).toBeVisible();
    await expect(tile('Files')).toHaveCount(0);
    await page.waitForTimeout(400); // grid items animate into place
    const [hosts, vendors] = [await tile('Hosts').boundingBox(), await tile('Vendors').boundingBox()];
    expect(hosts && vendors).toBeTruthy();
    const grid = (await page.locator('.react-grid-layout').boundingBox())!;
    const main = (await page.getByRole('main').boundingBox())!;
    expect(grid.x + grid.width).toBeLessThanOrEqual(main.x + main.width + 1);
    if (grid.width >= 768) expect(Math.abs(hosts!.y - vendors!.y)).toBeLessThan(2);
    else expect(vendors!.y).toBeGreaterThan(hosts!.y + hosts!.height - 2);
    for (const name of ['Hosts', 'Vendors', 'Software']) {
      const box = await tile(name).boundingBox();
      expect(box!.x + box!.width).toBeLessThanOrEqual(grid.x + grid.width + 1);
    }
    // The hidden Files chart leaves no hole: Software moves up beside nothing else.
    if (grid.width >= 768) await expect.poll(async () => (await tile('Software').boundingBox())!.x).toBeLessThan(hosts!.x + 2);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    expect(errors).toEqual([]);
  });
}
