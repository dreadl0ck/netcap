import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';
import { initializeI18n, i18n } from '@dreadl0ck/netcap-ui/i18n';
import { directCatalogBundle } from '@dreadl0ck/netcap-ui/i18n/direct';
import { removedCatalogBundle } from '@dreadl0ck/netcap-ui/i18n/removed';

const [origin, runId] = process.argv.slice(2);
assert.match(origin || '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.equal((await (await fetch(`${origin}/__font_test`)).json()).runId, runId);
initializeI18n({ locale: 'zh-Hans', bundles: [directCatalogBundle, removedCatalogBundle] });
const messages = ['ui', 'direct', 'removed'].map(ns => JSON.stringify(i18n.getResourceBundle('zh-Hans', ns))).join('');
const glyphs = [...new Set([...messages].filter(c => /\p{Script=Han}/u.test(c)))].join('');
assert.ok(glyphs.length > 0 && messages.includes('关闭'));

const browser = await chromium.launch({ channel: 'chrome', ...(process.env.NETCAP_TEST_CHROME ? { executablePath: process.env.NETCAP_TEST_CHROME } : {}) });
const context = await browser.newContext({ serviceWorkers: 'block' });
const unexpected = [], errors = [], fontRequests = [];
try {
  await context.route('**/*', async route => {
    if (new URL(route.request().url()).origin !== origin) {
      unexpected.push(route.request().url());
      return route.abort('blockedbyclient');
    }
    await route.continue();
  });
  const page = await context.newPage();
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error' && /font|CORS|Content Security Policy/i.test(message.text())) errors.push(message.text()); });
  page.on('response', response => {
    if (response.url().endsWith('.woff2')) fontRequests.push(response);
  });
  await page.goto(`${origin}/`, { waitUntil: 'load' });
  await page.waitForFunction(() => {
    const faces = [...document.fonts].filter(face => face.family.includes('Noto Sans SC Variable'));
    return faces.length === 101 && faces.every(face => face.status === 'loaded');
  });
  const parsedFaces = await page.evaluate(async text => {
    document.getElementById('font-probe').textContent = text;
    await document.fonts.load('400 20px "Noto Sans SC Variable"', text);
    await document.fonts.ready;
    return [...document.styleSheets].flatMap(sheet => [...sheet.cssRules]).filter(rule => rule instanceof CSSFontFaceRule).map(rule => ({ family: rule.style.fontFamily, weight: rule.style.fontWeight, src: rule.style.src }));
  }, glyphs);
  assert.equal(parsedFaces.length, 101);
  assert.ok(parsedFaces.every(face => face.family.includes('Noto Sans SC Variable') && face.weight === '100 900' && !face.src.includes('local(')));
  const cdp = await context.newCDPSession(page);
  await cdp.send('DOM.enable'); await cdp.send('CSS.enable');
  const { root } = await cdp.send('DOM.getDocument');
  const { nodeId } = await cdp.send('DOM.querySelector', { nodeId: root.nodeId, selector: '#font-probe' });
  const { fonts } = await cdp.send('CSS.getPlatformFontsForNode', { nodeId });
  assert.ok(fonts.length > 0);
  assert.ok(fonts.every(font => font.isCustomFont), `System-font fallback used: ${JSON.stringify(fonts)}`);
  assert.equal(fonts.reduce((n, font) => n + font.glyphCount, 0), [...glyphs].length);

  const frameAttached = page.waitForEvent('frameattached');
  await page.evaluate(() => {
    const iframe = document.createElement('iframe');
    iframe.title = 'Font chart'; iframe.sandbox = 'allow-scripts allow-downloads'; iframe.src = '/chart';
    document.body.append(iframe);
  });
  const frame = await frameAttached;
  await frame.waitForURL(`${origin}/chart`);
  await frame.waitForFunction(() => window.echarts?.getInstanceByDom(document.getElementById('font-chart')));
  const chartResult = await frame.evaluate(async text => {
    await document.fonts.load('400 20px "Noto Sans SC Variable"', text);
    await document.fonts.ready;
    const chart = window.echarts.getInstanceByDom(document.getElementById('font-chart'));
    const option = chart.getOption();
    return {
      origin: window.origin, family: option.textStyle.fontFamily,
      axis: option.xAxis[0].data[0], selected: option.legend[0].selected.Requests,
      zoom: option.dataZoom[0].start, value: option.series[0].data[0],
      faces: [...document.fonts].filter(face => face.status === 'loaded').length,
      title: option.title[0].text,
    };
  }, glyphs);
  assert.equal(chartResult.origin, 'null');
  assert.ok(chartResult.family.includes('Noto Sans SC Variable'));
  assert.ok(chartResult.faces > 0);
  assert.equal(chartResult.axis, '捕获样本'); assert.equal(chartResult.value, 5);
  assert.equal(chartResult.selected, false); assert.equal(chartResult.zoom, 12);
  assert.match(chartResult.title, /\p{Script=Han}/u);
  let opaqueFontRequests = 0;
  for (const response of fontRequests) {
    assert.equal(response.status(), 200);
    if ((await response.request().allHeaders()).origin === 'null') {
      opaqueFontRequests++;
      assert.equal(response.headers()['access-control-allow-origin'], '*');
    }
  }
  assert.ok(opaqueFontRequests > 0, 'must actually load fonts in the opaque-origin frame');
  assert.deepEqual(unexpected, []); assert.deepEqual(errors, []);
  console.log(JSON.stringify({ executionClass: 'ui-mocked', runId, catalogHanGlyphs: [...glyphs].length, customFonts: fonts.map(font => ({ family: font.familyName, glyphs: font.glyphCount })), opaqueFontRequests, externalRequests: unexpected.length, chartResult }));
} finally {
  await context.close();
  await browser.close();
}
