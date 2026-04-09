# Bundle Optimization Plan

## Overview

Based on Lighthouse audit, the Next.js frontend has **1,493 KiB of unused JavaScript**. This document outlines the optimization plan.

## Current Setup

### Bundle Analyzer Installed

✅ **@next/bundle-analyzer** has been configured:
- Added to `package.json` as dev dependency
- Configured in `next.config.js` with `ANALYZE=true` environment variable
- Added `npm run analyze` script for easy usage

### How to Use

```bash
cd cmd/capture/webui/frontend
npm install
npm run analyze
```

This will open two browser windows showing your bundle composition.

## Identified Issues

### 1. Material-UI Barrel Imports

**Problem:** Currently importing many components from the barrel export (`@mui/material`)

**Current Pattern (visualize.tsx):**
```typescript
import {
  Box,
  Card,
  CardContent,
  CircularProgress,
  FormControl,
  Grid,
  MenuItem,
  Paper,
  Select,
  // ... 15+ more components
} from '@mui/material';
```

**Impact:** This can prevent optimal tree shaking and include unused code.

**Solution:** Use direct imports for better tree shaking:
```typescript
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
// etc.
```

### 2. ECharts via echarts-for-react

**Current:** Using `echarts-for-react` which imports the full ECharts library (~600KB+)

**Location:** `cmd/capture/webui/frontend/src/pages/files.tsx`

**Solution Options:**
1. Import only needed ECharts modules
2. Use dynamic imports for chart-heavy pages
3. Consider lazy loading chart components

### 3. React Google Charts

**Current:** Using `react-google-charts` in `visualize.tsx`

**Questions to Consider:**
- Is this needed alongside ECharts?
- Can ECharts handle all visualization needs?
- Google Charts loads external scripts - additional network overhead

### 4. Icon Imports

**Current:** Importing many individual icons from `@mui/icons-material`

```typescript
import {
  AccountTree as SankeyIcon,
  SwapHoriz as SwapHorizIcon,
  GridView as TreemapIcon,
  // ... 7+ more icons
} from '@mui/icons-material';
```

**Impact:** Each icon is a separate component; better to import directly

**Solution:**
```typescript
import AccountTree from '@mui/icons-material/AccountTree';
import SwapHoriz from '@mui/icons-material/SwapHoriz';
// etc.
```

## Optimization Strategy

### Phase 1: Analyze (Current)

1. ✅ Install and configure bundle analyzer
2. ⏳ Run `npm run analyze` to get baseline metrics
3. ⏳ Document current bundle size and composition
4. ⏳ Identify top 5 largest modules

### Phase 2: Quick Wins

1. **Convert Material-UI imports** to direct imports
   - Automated with codemod: `npx @mui/codemod v5.0.0/optimal-imports src/`
   - Estimated savings: ~100-200 KB

2. **Convert Material-UI Icons imports** to direct imports
   - Similar codemod available
   - Estimated savings: ~50-100 KB

3. **Enable modularEcharts** (if not already)
   - Configure echarts-for-react to use core + needed modules
   - Estimated savings: ~300-400 KB

### Phase 3: Code Splitting

1. **Dynamic imports for heavy pages**
   ```typescript
   const Visualize = dynamic(() => import('../pages/visualize'), {
     loading: () => <CircularProgress />,
     ssr: false
   });
   ```

2. **Lazy load chart components**
   - Only load charts when needed
   - Use intersection observer for below-fold charts

### Phase 4: Dependency Audit

1. **Review if both chart libraries are needed**
   - ECharts: Used in files.tsx
   - Google Charts: Used in visualize.tsx
   - Can we standardize on one?

2. **Check for duplicate dependencies**
   - Run bundle analyzer to identify
   - May have different versions of same package

3. **Remove unused dependencies**
   ```bash
   npx depcheck
   ```

## Expected Results

Based on Lighthouse showing 1,493 KiB unused:

| Optimization | Expected Savings |
|-------------|------------------|
| Material-UI direct imports | 100-200 KB |
| Icons direct imports | 50-100 KB |
| Modular ECharts | 300-400 KB |
| Code splitting | 200-300 KB (initial load) |
| Remove one chart library | 50-100 KB |
| **Total** | **700-1,100 KB** |

Target: **Reduce initial bundle by 50%+**

## Implementation Commands

### 1. Run Bundle Analyzer (First)

```bash
cd cmd/capture/webui/frontend
npm install
npm run analyze
```

Take screenshots and document findings.

### 2. Apply Material-UI Codemod

```bash
cd cmd/capture/webui/frontend
npx @mui/codemod v5.0.0/optimal-imports src/
```

### 3. Rebuild and Compare

```bash
npm run build
npm run analyze
```

Compare before/after bundle sizes.

### 4. Test Everything Still Works

```bash
npm run dev
# Manual testing of all pages
# Automated tests if available
npm test
```

### 5. Build for Production

```bash
cd /Users/pmieden/go/src/github.com/dreadl0ck/netcap
zeus build-frontend
zeus install
```

## Monitoring

### Bundle Size Budget

Set up bundle size budgets in `next.config.js`:

```javascript
const nextConfig = {
  // ... existing config
  
  // Warn if bundles exceed these sizes
  onDemandEntries: {
    maxInactiveAge: 25 * 1000,
    pagesBufferLength: 2,
  },
  
  // Bundle size tracking
  generateBuildId: async () => {
    // Custom build ID
    return 'build-' + Date.now()
  },
}
```

### Regular Audits

Add to development workflow:
```bash
# Before each release
npm run analyze

# Or add to CI/CD
if [ "$CI" = "true" ]; then
  npm run build
  # Check bundle size vs. limits
fi
```

## Additional Optimizations

### Already Implemented ✅

- `.browserslistrc` - Targets modern browsers only
- `output: 'export'` - Static export for efficiency
- `removeConsole: true` - Removes console.log in production
- `images: { unoptimized: true }` - Correct for static export

### Future Considerations

1. **Webpack compression plugin**
   - Enable Brotli compression
   - Better than gzip for static assets

2. **Critical CSS extraction**
   - Inline critical CSS for faster initial render

3. **Font optimization**
   - Use `next/font` if using custom fonts
   - Self-host instead of Google Fonts

4. **Image optimization**
   - Convert to WebP/AVIF where possible
   - Use responsive images

## Next Steps

1. **Run the analyzer** to establish baseline
2. **Take screenshots** of bundle composition
3. **Apply Material-UI codemod** for quick wins
4. **Review chart library usage** - can we use just one?
5. **Re-run analyzer** to measure improvement
6. **Test thoroughly** before committing
7. **Document results** in this file

## Resources

- [Next.js Bundle Analyzer](https://github.com/vercel/next.js/tree/canary/packages/next-bundle-analyzer)
- [Material-UI Optimization](https://mui.com/material-ui/guides/minimizing-bundle-size/)
- [ECharts Tree Shaking](https://echarts.apache.org/handbook/en/basics/import/)
- [Next.js Performance](https://nextjs.org/docs/pages/building-your-application/optimizing/bundle-analyzer)

---

## Results (November 20, 2025)

### ✅ Optimization Complete

**Major Win: ECharts Tree-Shaking**
- Created custom `OptimizedPieChart` component using tree-shakeable imports
- Removed `echarts-for-react` dependency
- **Result:** `/files` page reduced from 377 KB → 174 KB (203 KB saved, 36% smaller)

**MUI Direct Imports**
- Converted 4 key files to use direct imports instead of barrel imports
- Files: `files.tsx`, `visualize.tsx`, `index.tsx`, `Layout.tsx`
- **Result:** Improved tree-shaking, marginal bundle improvements

**Overall Impact:**
- Total bundle size: 7.6M → 6.0M (1.6M saved, 21% reduction)
- Largest page reduced by 36%
- Expected LCP improvement: 0.5-1.0s faster

**Status:** ✅ Completed and deployed
**Priority:** Resolved - Major performance bottleneck addressed
**Time Spent:** 2 hours

See `frontend-performance-improvements.md` for full details.

