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

// All entry points - lib is included to ensure types are generated correctly
const entries = {
  'index': 'src/index.ts',
  'providers/index': 'src/providers/index.ts',
  'components/index': 'src/components/index.ts',
  'hooks/index': 'src/hooks/index.ts',
  'pages/index': 'src/pages/index.ts',
  'contexts/index': 'src/contexts/index.ts',
  'adapters/react-router': 'src/adapters/react-router.tsx',
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
  // React Router - all subpaths
  'react-router',
  /^react-router\//,
];

export default defineConfig({
  // All entries including lib - with "use client" directive for React components
  // The lib/index entry is pure utilities but including here ensures types are generated
  entry: entries,
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
});

