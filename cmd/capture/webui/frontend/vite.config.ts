/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    // esbuild >=0.28 errors when lowering modern syntax (e.g. destructuring)
    // to mixed targets like vite's default "es2020". Pin a modern target that
    // natively supports the syntax used by React 19 output.
    target: 'es2022',
  },
  esbuild: {
    drop: mode === 'production' ? ['console'] : [],
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8080',
    },
  },
}))
