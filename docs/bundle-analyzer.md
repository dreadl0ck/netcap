# Webpack Bundle Analyzer for Next.js Frontend

This document explains how to use the webpack bundle analyzer to identify and remove unused JavaScript in the Netcap Web UI.

## Setup

The bundle analyzer has been configured in the Next.js frontend with the following components:

1. **@next/bundle-analyzer** - Installed as a dev dependency
2. **next.config.js** - Configured to enable the analyzer when `ANALYZE=true`
3. **package.json** - Added `analyze` script for easy usage

## Usage

### Step 1: Install Dependencies

First, make sure you have installed the dependencies:

```bash
cd cmd/capture/webui/frontend
npm install
```

### Step 2: Run the Bundle Analyzer

Run the analyzer with:

```bash
npm run analyze
```

Or directly:

```bash
ANALYZE=true npm run build
```

This will:
- Build your Next.js application
- Generate bundle analysis reports
- Automatically open two browser windows showing:
  - **Client bundle** - JavaScript sent to the browser
  - **Server bundle** - Server-side code (if applicable)

### Step 3: Analyze the Results

The bundle analyzer shows:

- **Size of each module** - Visualized as rectangles (larger = bigger file)
- **Gzip size** - Actual size users download
- **Parsed size** - Uncompressed size
- **Stat size** - Size before any processing

#### What to Look For

1. **Large dependencies** - Check if they're all necessary
   - Example: If you're using only a small part of a large library
   
2. **Duplicate packages** - Same package included multiple times
   - Look for different versions of the same library
   
3. **Unused exports** - Large modules where only small parts are used
   - Consider importing only what you need

4. **Heavy polyfills** - Unnecessary browser compatibility code
   - Already mitigated with `.browserslistrc` for modern browsers

## Current Dependencies to Review

Based on the Lighthouse report showing 1,493 KiB of unused JavaScript, review these areas:

### 1. ECharts (Currently ~600KB+)

ECharts is the largest dependency. Consider:

```typescript
// Instead of importing everything:
import * as echarts from 'echarts';

// Import only needed components:
import * as echarts from 'echarts/core';
import { BarChart, LineChart, PieChart } from 'echarts/charts';
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';

echarts.use([
  BarChart, LineChart, PieChart,
  GridComponent, TooltipComponent, LegendComponent,
  CanvasRenderer
]);
```

### 2. Material-UI (@mui/material)

If you're not using all components:

```typescript
// Instead of:
import { Button, TextField, ... } from '@mui/material';

// Use direct imports:
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
```

### 3. React Google Charts

Consider if this is needed alongside ECharts, or if ECharts can handle all visualization needs.

## Optimization Strategies

### 1. Code Splitting

Use dynamic imports for heavy components:

```typescript
import dynamic from 'next/dynamic';

const HeavyChart = dynamic(() => import('../components/HeavyChart'), {
  loading: () => <p>Loading chart...</p>,
  ssr: false // Disable server-side rendering if not needed
});
```

### 2. Tree Shaking

Ensure imports support tree shaking:

```typescript
// Good - allows tree shaking
import { specific } from 'library';

// Bad - imports everything
import * as library from 'library';
```

### 3. Remove Unused Dependencies

After analysis, remove packages that aren't being used:

```bash
npm uninstall unused-package
```

### 4. Use Bundle Analyzer Regularly

Add to your CI/CD pipeline or run regularly during development:

```bash
# Before releasing
npm run analyze

# Check the size limits
npm run build
```

## Next Steps

1. Run `npm run analyze` to see the current bundle composition
2. Identify the largest chunks and modules
3. Review if all large dependencies are necessary
4. Implement optimizations (tree shaking, dynamic imports, etc.)
5. Re-run analyzer to verify improvements
6. Use `zeus build-frontend` to rebuild with optimizations

## Additional Resources

- [Next.js Bundle Analyzer](https://github.com/vercel/next.js/tree/canary/packages/next-bundle-analyzer)
- [Next.js Optimization Docs](https://nextjs.org/docs/pages/building-your-application/optimizing)
- [Webpack Bundle Analyzer](https://github.com/webpack-contrib/webpack-bundle-analyzer)

## Current Status

As of the Lighthouse audit, the application has:
- **1,493 KiB** of unused JavaScript (potential savings)
- **1,746.2 KiB** total transfer size from netcap.io
- **327.9 KiB** from external libraries (echarts)

Target: Reduce bundle size by at least 50% through selective imports and code splitting.

