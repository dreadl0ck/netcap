import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import { build } from 'vite';
import { initializeI18n, i18n } from '@dreadl0ck/netcap-ui/i18n';
import { directCatalogBundle } from '@dreadl0ck/netcap-ui/i18n/direct';
import { removedCatalogBundle } from '@dreadl0ck/netcap-ui/i18n/removed';
import { byteLimit, fontFamily, fontPackage, fontPath, fontVersion, prepareFonts, verifyFonts } from './prepare-fonts.mjs';

test('supplier terms are included in the canonical community license inventory', () => {
  const notices = readFileSync(resolve('../../../..', 'legal/THIRD_PARTY_LICENSES.txt'), 'utf8');
  assert.ok(notices.includes(`${fontPackage} ${fontVersion}\nLicense inventory: OFL-1.1`));
  const fontNotice = notices.slice(notices.indexOf(`${fontPackage} ${fontVersion}`));
  assert.ok(fontNotice.includes('SIL OPEN FONT LICENSE'));
});

test('bundles every Chinese catalog glyph in declared Unicode subsets, once per variable face', () => {
  const root = mkdtempSync(join(tmpdir(), 'netcap-fonts-'));
  try {
    prepareFonts(root);
    const result = verifyFonts(root);
    assert.ok(result.shippedBytes < byteLimit);
    const css = readFileSync(join(root, 'index.css'), 'utf8');
    assert.equal((css.match(/@font-face/g) || []).length, result.subsets);
    assert.equal(readdirSync(root).filter(name => name.endsWith('.woff2')).length, result.subsets);
    assert.ok(!css.includes('local(') && !css.includes('https:') && !css.includes('http:'));
    initializeI18n({ locale: 'zh-Hans', bundles: [directCatalogBundle, removedCatalogBundle] });
    const catalogs = ['ui', 'direct', 'removed'].map(ns => i18n.getResourceBundle('zh-Hans', ns));
    assert.ok(catalogs.every(catalog => Object.keys(catalog || {}).length > 0));
    const text = JSON.stringify(catalogs);
    const glyphs = [...new Set([...text].filter(c => /\p{Script=Han}/u.test(c)))];
    assert.ok(glyphs.length > 0 && text.includes('关闭'), 'catalog inventory must contain real Chinese UI text');
    const ranges = [...css.matchAll(/unicode-range:\s*([^;]+);/g)].flatMap(([, value]) => value.split(',').map(range => {
      const [, lo, hi] = /^\s*U\+([0-9a-f?]+)(?:-([0-9a-f]+))?\s*$/i.exec(range);
      return [parseInt(lo.replaceAll('?', '0'), 16), parseInt((hi || lo).replaceAll('?', 'f'), 16)];
    }));
    for (const glyph of glyphs) assert.ok(ranges.some(([lo, hi]) => glyph.codePointAt(0) >= lo && glyph.codePointAt(0) <= hi), `Unpackaged glyph ${glyph}`);
    console.log(JSON.stringify({ family: fontFamily, catalogHanGlyphs: glyphs.length, fontBytes: result.fontBytes, shippedBytes: result.shippedBytes }));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('packaging checks reject missing, modified and surplus font assets', () => {
  const root = mkdtempSync(join(tmpdir(), 'netcap-font-check-'));
  try {
    prepareFonts(root);
    const file = readdirSync(root).find(name => name.endsWith('.woff2'));
    rmSync(join(root, file));
    assert.throws(() => verifyFonts(root), /Missing or surplus/);
    prepareFonts(root);
    writeFileSync(join(root, 'index.css'), 'stale stylesheet');
    assert.throws(() => verifyFonts(root), /Stale font asset/);
    prepareFonts(root);
    writeFileSync(join(root, 'unused-static-700.woff2'), 'unused');
    assert.throws(() => verifyFonts(root), /Missing or surplus/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Vite packages the shared stylesheet URL without emitting duplicate hashed font resources', async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'netcap-font-build-')));
  try {
    const publicFonts = join(root, 'public', fontPath);
    prepareFonts(publicFonts);
    writeFileSync(join(root, 'index.html'), '<!doctype html><script type="module" src="/main.js"></script>');
    writeFileSync(join(root, 'main.js'), "import './fontStylesheet.ts';");
    writeFileSync(join(root, 'fontStylesheet.ts'), readFileSync('src/fontStylesheet.ts'));
    await build({ configFile: false, root, envDir: join(root, 'no-env'), logLevel: 'silent', build: { outDir: 'dist', target: 'es2022' } });
    const dist = join(root, 'dist');
    verifyFonts(join(dist, fontPath));
    assert.deepEqual(readdirSync(join(dist, 'assets')).filter(name => /\.woff2?$/.test(name)), []);
    const javascript = readdirSync(join(dist, 'assets')).filter(name => name.endsWith('.js')).map(name => readFileSync(join(dist, 'assets', name), 'utf8')).join('');
    assert.ok(javascript.includes(`${fontPath}index.css`) && javascript.includes(fontFamily));
    const host = readFileSync(resolve('src/main.tsx'), 'utf8');
    assert.ok(host.includes("import './fontStylesheet'"));
    assert.ok(!host.includes("import '@fontsource-variable/noto-sans-sc"));
  } finally { rmSync(root, { recursive: true, force: true }); }
});
