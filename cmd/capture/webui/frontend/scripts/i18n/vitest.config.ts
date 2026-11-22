import { defineConfig } from 'vitest/config';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const require = createRequire(import.meta.url);
const temporary = process.env.NETCAP_I18N_DEPS_ROOT;
const external = temporary ? createRequire(path.join(temporary, 'package.json')) : require;

export default defineConfig({
  root,
  resolve: {
    alias: [
      ...['i18next', 'i18next-icu', 'react-i18next', 'intl-messageformat'].map(name => ({ find: name, replacement: external.resolve(name) })),
      { find: /^@dreadl0ck\/netcap-ui\/i18n$/, replacement: path.join(root, 'packages/netcap-ui/src/lib/i18n.ts') },
      { find: /^@dreadl0ck\/netcap-ui\/i18n\/(direct|removed|mui)$/, replacement: path.join(root, 'packages/netcap-ui/src/lib/i18n/$1.ts') },
      { find: /^react$/, replacement: require.resolve('react') },
    ],
    dedupe: ['react', 'react-dom'],
  },
  test: {
    environment: 'jsdom',
    include: ['packages/netcap-ui/src/lib/i18n/**/*.test.{ts,tsx}', 'packages/netcap-ui/src/components/ChartFrame.appearance.test.tsx'],
    server: { deps: { inline: ['react-i18next'] } },
  },
});
