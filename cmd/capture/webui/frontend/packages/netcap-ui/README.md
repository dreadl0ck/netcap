# @dreadl0ck/netcap-ui

Netcap UI component library - reusable React components for building network analysis interfaces.

Published to [GitHub Packages](https://github.com/dreadl0ck/netcap/packages).

## Installation

First, configure npm to use GitHub Packages for the `@dreadl0ck` scope. Create or edit `~/.npmrc`:

```
@dreadl0ck:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=YOUR_GITHUB_TOKEN
```

Then install:

```bash
npm install @dreadl0ck/netcap-ui
# or
yarn add @dreadl0ck/netcap-ui
# or
pnpm add @dreadl0ck/netcap-ui
```

### Peer Dependencies

This library requires the following peer dependencies:

```json
{
  "react": "^18.0.0 || ^19.0.0",
  "react-dom": "^18.0.0 || ^19.0.0",
  "@mui/material": "^5.0.0",
  "@mui/icons-material": "^5.0.0",
  "@emotion/react": "^11.0.0",
  "@emotion/styled": "^11.0.0",
  "swr": "^2.0.0"
}
```

## Quick Start

### Next.js

The easiest way to use this library in Next.js is with the built-in adapter:

```tsx
// _app.tsx
import { NextjsNetcapProvider } from '@dreadl0ck/netcap-ui/adapters/nextjs';
import type { AppProps } from 'next/app';

export default function App({ Component, pageProps }: AppProps) {
  return (
    <NextjsNetcapProvider backendUrl="http://localhost:8080">
      <Component {...pageProps} />
    </NextjsNetcapProvider>
  );
}
```

Note: `NextjsNetcapProvider` includes `LearnModeProvider` by default. To disable it, pass `includeLearnMode={false}`.

Then use components in your pages:

```tsx
// pages/my-page.tsx
import { Layout, useNetcapApi } from '@dreadl0ck/netcap-ui';
import useSWR from 'swr';

export default function MyPage() {
  const api = useNetcapApi();
  const { data: status } = useSWR('status', () => api.getStatus());

  return (
    <Layout title="My Page">
      <div>
        {status?.isProcessing ? 'Processing...' : 'Ready'}
      </div>
    </Layout>
  );
}
```

### React Router (or other frameworks)

For non-Next.js apps, configure the provider manually:

```tsx
import { 
  NetcapProvider, 
  LearnModeProvider,
  Layout 
} from '@dreadl0ck/netcap-ui';
import { 
  useNavigate, 
  useLocation, 
  useSearchParams, 
  Link 
} from 'react-router-dom';

function App() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  const config = {
    backendUrl: 'http://localhost:8080',
    router: {
      pathname: location.pathname,
      query: Object.fromEntries(searchParams),
      isReady: true,
      push: navigate,
    },
    Link: ({ href, children, ...props }) => (
      <Link to={href} {...props}>{children}</Link>
    ),
  };

  return (
    <NetcapProvider config={config}>
      <LearnModeProvider>
        <Routes>
          <Route path="/" element={
            <Layout title="Dashboard">
              <Dashboard />
            </Layout>
          } />
        </Routes>
      </LearnModeProvider>
    </NetcapProvider>
  );
}
```

Note: For non-Next.js apps, you need to manually include `LearnModeProvider` if you want learn mode functionality.

## API Reference

### Providers

#### `NetcapProvider`

The main provider that configures the library.

```tsx
interface NetcapConfig {
  backendUrl: string;           // Backend API URL
  router: RouterAdapter;        // Router adapter
  Link: LinkComponent;          // Link component
  fetch?: typeof fetch;         // Optional custom fetch
  debug?: boolean;              // Enable debug mode
}
```

#### `LearnModeProvider`

Provides the learn mode context for interactive UI hints.

### Hooks

#### `useNetcapRouter()`

Returns a router object compatible with the configured router:

```tsx
const router = useNetcapRouter();

router.pathname      // Current path
router.query         // Query parameters
router.isReady       // Router ready state
router.push(path)    // Navigate to path
router.isActive(path) // Check if path is active
router.getQueryParam(key) // Get single query param
```

#### `useNetcapApi()`

Returns the configured API client:

```tsx
const api = useNetcapApi();

const status = await api.getStatus();
const hosts = await api.getInputFiles();
```

### Components

#### `Layout`

Main layout component with navigation sidebar:

```tsx
<Layout 
  title="Page Title"
  headerAction={<MyHeaderComponent />}
  topPadding="100px"
>
  {children}
</Layout>
```

#### `FileSelectorHeader`

PCAP file selector for page headers:

```tsx
<FileSelectorHeader
  inputFiles={files}
  status={status}
  switchingFile={isLoading}
  onFileChange={handleChange}
/>
```

#### `NetcapLink`

Navigation link component that uses the configured Link:

```tsx
<NetcapLink href="/hosts">View Hosts</NetcapLink>
```

### Utility Functions

```tsx
import { formatBytes, formatTimestamp, formatDuration } from '@dreadl0ck/netcap-ui';

formatBytes(1024)         // "1 KB"
formatTimestamp(Date.now()) // "11/28/2024, 10:30:00 AM"
formatDuration(3661)      // "1h 1m"
```

## Building

```bash
cd packages/netcap-ui
npm install
npm run build
```

## License

GPL-3.0

