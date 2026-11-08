import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

test('renderer-local: coverage survives actual ECharts SVG and PNG exports', async ({ page, baseURL }) => {
  const unexpected: string[] = [], errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  const html = await readFile(resolve('e2e/analyst-renderer.html'), 'utf8');
  await page.context().route('**/*', route => {
    const url = new URL(route.request().url());
    if (url.origin !== baseURL) { unexpected.push(url.href); return route.abort(); }
    if (url.pathname === '/api/analyst-renderer-fixture') return route.fulfill({ contentType: 'text/html', body: html });
    if (url.pathname === '/static/echarts/echarts.min.js') return route.continue();
    unexpected.push(url.href); return route.abort();
  });
  await page.goto('/api/analyst-renderer-fixture');
  await expect(page.getByRole('note')).toContainText('sampling/completeness unreported');
  await expect.poll(() => page.evaluate(() => {
    const ec = (window as any).echarts;
    return ['svg', 'canvas'].every(id => ec.getInstanceByDom(document.getElementById(id)).getOption().graphic?.[0]?.elements?.some((element: any) => element.id === 'netcap-coverage'));
  })).toBe(true);
  const exports = await page.evaluate(() => {
    const ec = (window as any).echarts;
    return { svg: ec.getInstanceByDom(document.getElementById('svg')).getDataURL({ type: 'svg' }), png: ec.getInstanceByDom(document.getElementById('canvas')).getDataURL({ type: 'png' }) };
  });
  const svg = decodeURIComponent(exports.svg.replace(/^data:image\/svg\+xml[^,]*,/, ''));
  expect(svg).toContain('Retained audit summaries');
  expect(svg).toContain('sampling/completeness unreported');
  expect(exports.png).toMatch(/^data:image\/png;base64,iVBOR/);
  expect(exports.png.length).toBeGreaterThan(1000);
  expect(unexpected).toEqual([]); expect(errors).toEqual([]);
});
