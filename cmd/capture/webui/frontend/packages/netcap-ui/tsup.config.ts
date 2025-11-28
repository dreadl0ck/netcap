/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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

// Shared external dependencies - these should never be bundled
// Using regex patterns to catch all subpaths (e.g., next/router, next/link, etc.)
const sharedExternals = [
  // React ecosystem - must be external to prevent context duplication
  'react',
  'react-dom',
  /^react\//,
  /^react-dom\//,
  // MUI
  '@mui/material',
  '@mui/icons-material',
  /^@mui\//,
  // Emotion
  '@emotion/react',
  '@emotion/styled',
  /^@emotion\//,
  // SWR
  'swr',
  /^swr\//,
  // Next.js - all subpaths
  'next',
  /^next\//,
];

export default defineConfig([
  // Client components build - with "use client" directive
  // splitting: true ensures shared code (like contexts) use a single instance
  {
    entry: clientEntries,
    format: ['cjs', 'esm'],
    dts: true,
    splitting: true,  // Enable code splitting to share context instances
    sourcemap: true,
    clean: true,
    external: sharedExternals,
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
    splitting: true,  // Enable code splitting for consistency
    sourcemap: true,
    external: sharedExternals,
  },
]);

