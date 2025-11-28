import { defineConfig } from 'tsup';

// Entry points that contain React components and need "use client" directive
const clientEntries = {
  'index': 'src/index.ts',
  'providers/index': 'src/providers/index.ts',
  'components/index': 'src/components/index.ts',
  'hooks/index': 'src/hooks/index.ts',
  'pages/index': 'src/pages/index.ts',
  'contexts/index': 'src/contexts/index.ts',
  'adapters/nextjs': 'src/adapters/nextjs.tsx',
};

// Entry points that are pure utilities (no React hooks/components)
const utilityEntries = {
  'lib/index': 'src/lib/index.ts',
};

export default defineConfig([
  // Client components build - with "use client" directive
  {
    entry: clientEntries,
    format: ['cjs', 'esm'],
    dts: true,
    splitting: false,
    sourcemap: true,
    clean: true,
    external: [
      'react',
      'react-dom',
      '@mui/material',
      '@mui/icons-material',
      '@emotion/react',
      '@emotion/styled',
      'swr',
      'next',
      'next/router',
      'next/link',
      'next/head',
    ],
    esbuildOptions(options) {
      options.banner = {
        js: '"use client";',
      };
    },
  },
  // Utility/library build - no "use client" directive
  {
    entry: utilityEntries,
    format: ['cjs', 'esm'],
    dts: true,
    splitting: false,
    sourcemap: true,
    external: [
      'react',
      'react-dom',
    ],
  },
]);

