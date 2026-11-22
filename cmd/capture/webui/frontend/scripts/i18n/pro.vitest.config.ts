import { defineConfig } from 'vitest/config';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const frontend = fileURLToPath(new URL('../../', import.meta.url));
const pro = path.resolve(frontend, '../../../../../netcap-pro/frontend');
const shared = path.join(frontend, 'packages/netcap-ui/src/lib');
const require = createRequire(path.join(pro, 'package.json'));
const runtime = process.env.NETCAP_I18N_DEPS_ROOT ? createRequire(path.join(process.env.NETCAP_I18N_DEPS_ROOT, 'package.json')) : require;

export default defineConfig({
  root: pro,
  server: { fs: { allow: [path.resolve(frontend, '../../../..'), path.resolve(pro, '..')] } },
  resolve: {
    alias: [
      { find: /^@dreadl0ck\/netcap-ui\/i18n$/, replacement: path.join(shared, 'i18n.ts') },
      { find: /^@dreadl0ck\/netcap-ui\/i18n\/(direct|removed|mui)$/, replacement: path.join(shared, 'i18n/$1.ts') },
      ...['i18next', 'i18next-icu', 'react-i18next', 'intl-messageformat'].map(name => ({ find: new RegExp('^' + name + '$'), replacement: runtime.resolve(name) })),
      ...['react', 'react/jsx-runtime', 'react/jsx-dev-runtime', 'react-dom', 'react-dom/client', 'swr', 'react-router'].map(name => ({ find: new RegExp('^' + name.replaceAll('/', '\\/') + '$'), replacement: require.resolve(name) })),
      { find: /^vitest$/, replacement: path.join(path.dirname(require.resolve('vitest/package.json')), 'dist/index.js') },
    ],
    dedupe: ['react', 'react-dom'],
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./vitest.setup.ts', path.join(frontend, 'scripts/i18n/pro.setup.ts')],
    include: ['src/components/OpenCaptureButton.test.tsx', 'src/components/LicenseGate.presentation.test.tsx', 'src/lib/presentation.test.tsx'],
    server: { deps: { inline: ['react-i18next', '@wailsio/runtime'] } },
  },
});
