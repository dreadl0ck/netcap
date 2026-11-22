import { test } from 'node:test';
import assert from 'node:assert/strict';
import { build } from 'vite';
import { frontend } from './config.mjs';

test('base localization entry excludes direct and removed-feature catalogs from the built module', async () => {
  async function bundled(entry) {
    const result = await build({
      configFile: false, root: frontend, logLevel: 'silent',
      build: {
        write: false, minify: false, target: 'es2022', lib: { entry, formats: ['es'] },
        rollupOptions: { external: ['react', 'i18next', 'react-i18next', 'i18next-icu', 'intl-messageformat', 'swr'] },
      },
    });
    return (Array.isArray(result) ? result : [result]).flatMap(output => output.output).filter(item => item.type === 'chunk').map(chunk => chunk.code).join('\n');
  }
  const base = await bundled('packages/netcap-ui/src/lib/i18n.ts');
  assert.ok(base.includes('Schließen'));
  assert.ok(base.includes('关闭'));
  assert.ok(!base.includes('Buy License'));
  assert.ok(!base.includes('Lizenzschlüssel'));
  assert.ok(!base.includes('Graph Analysis'));
  assert.ok(!base.includes('Packet injection'));
  for (const exclusiveCopy of ['YARA Rules: Upload and manage YARA rules', 'Configure packet injection and manipulation rules.', 'Configure Deep Packet Inspection modules.', 'Direct-download builds use nDPI']) assert.ok(!base.toLowerCase().includes(exclusiveCopy.toLowerCase()), exclusiveCopy);
  const direct = await bundled('packages/netcap-ui/src/lib/i18n/direct.ts');
  assert.ok(direct.includes('Buy License'));
  const removed = await bundled('packages/netcap-ui/src/lib/i18n/removed.ts');
  assert.ok(removed.includes('Graph Analysis'));
});
