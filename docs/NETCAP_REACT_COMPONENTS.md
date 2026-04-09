# NETCAP React Component Set

> A comprehensive React component library for building network analysis interfaces

## Overview

The `@netcap/ui` package provides a complete set of React components, hooks, and utilities for building network traffic analysis interfaces. It's designed to be **framework-agnostic** and can be used with Next.js, React Router, or any other React application.

### Key Features

- 🎨 **30+ Pre-built Page Components** - Complete pages for hosts, connections, alerts, and more
- 🔌 **Framework Agnostic** - Works with Next.js, React Router, Remix, or vanilla React
- 🎯 **Type-Safe** - Full TypeScript support with comprehensive type definitions
- 🔄 **Backend Integration** - Built-in API client with SWR for data fetching
- 📊 **Syntax Highlighting** - BPF filters, regex patterns, and filter expressions
- 🎓 **Learn Mode** - Interactive UI hints for user onboarding

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
   - [Next.js](#nextjs)
   - [React Router](#react-router)
3. [Architecture](#architecture)
4. [Providers](#providers)
5. [Hooks](#hooks)
6. [Components](#components)
7. [Pages](#pages)
8. [Utility Functions](#utility-functions)
9. [Types Reference](#types-reference)
10. [Examples](#examples)

---

## Installation

```bash
npm install @netcap/ui
# or
yarn add @netcap/ui
# or
pnpm add @netcap/ui
```

### Peer Dependencies

The library requires these peer dependencies:

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

For Next.js applications:
```json
{
  "next": "^13.0.0 || ^14.0.0 || ^15.0.0 || ^16.0.0"
}
```

---

## Quick Start

### Next.js

The easiest way to get started with Next.js is using the built-in adapter:

```tsx
// pages/_app.tsx
import { NextjsNetcapProvider } from '@netcap/ui/adapters/nextjs';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import type { AppProps } from 'next/app';

const theme = createTheme({
  palette: { mode: 'dark' },
});

export default function App({ Component, pageProps }: AppProps) {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <NextjsNetcapProvider backendUrl="http://localhost:8080">
        <Component {...pageProps} />
      </NextjsNetcapProvider>
    </ThemeProvider>
  );
}
```

Then use pages directly:

```tsx
// pages/hosts.tsx
import { HostsPage } from '@netcap/ui/pages';

export default function Hosts() {
  return <HostsPage />;
}
```

### React Router

For React Router applications, configure the provider manually:

```tsx
import { 
  NetcapProvider, 
  LearnModeProvider 
} from '@netcap/ui';
import { 
  useNavigate, 
  useLocation, 
  useSearchParams, 
  Link,
  Routes,
  Route 
} from 'react-router-dom';
import { DashboardPage, HostsPage } from '@netcap/ui/pages';

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
          <Route path="/" element={<DashboardPage />} />
          <Route path="/hosts" element={<HostsPage />} />
        </Routes>
      </LearnModeProvider>
    </NetcapProvider>
  );
}
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Your Application                      │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────┐    │
│  │           NetcapProvider / Adapter              │    │
│  │  (Provides: router, Link, backendUrl, api)      │    │
│  └─────────────────────────────────────────────────┘    │
│           │                     │                        │
│     ┌─────┴─────┐         ┌────┴────┐                   │
│     │   Hooks   │         │ Context │                   │
│     │           │         │         │                   │
│     │ useNetcap │         │ Learn   │                   │
│     │ Router()  │         │ Mode    │                   │
│     │           │         │         │                   │
│     │ useNetcap │         └────┬────┘                   │
│     │ Api()     │              │                        │
│     └─────┬─────┘              │                        │
│           │                    │                        │
│     ┌─────┴────────────────────┴─────┐                  │
│     │         Components & Pages      │                  │
│     │                                 │                  │
│     │  Layout, FileSelectorHeader,   │                  │
│     │  DashboardPage, HostsPage...   │                  │
│     └─────────────────────────────────┘                  │
│                       │                                  │
│                       ▼                                  │
│     ┌─────────────────────────────────┐                  │
│     │      Netcap Backend API         │                  │
│     │    (http://localhost:8080)      │                  │
│     └─────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────┘
```

---

## Providers

### NetcapProvider

The core provider that configures the library for your application.

```tsx
import { NetcapProvider } from '@netcap/ui/providers';

interface NetcapConfig {
  /** Backend API URL (e.g., 'http://localhost:8080') */
  backendUrl: string;
  
  /** Router adapter for navigation */
  router: RouterAdapter;
  
  /** Link component for navigation links */
  Link: LinkComponent;
  
  /** Optional: Custom API implementation (partial overrides) */
  api?: PartialApi;
  
  /** Optional: Enable debug logging */
  debug?: boolean;
}

interface RouterAdapter {
  pathname: string;
  query: Record<string, string | string[] | undefined>;
  isReady: boolean;
  push: (path: string) => void | Promise<boolean>;
  replace?: (path: string) => void | Promise<boolean>;
}
```

### NextjsNetcapProvider

Pre-configured provider for Next.js applications.

```tsx
import { NextjsNetcapProvider } from '@netcap/ui/adapters/nextjs';

interface NextjsNetcapProviderProps {
  children: ReactNode;
  /** Backend URL for the Netcap API */
  backendUrl: string;
  /** Enable debug mode (default: false) */
  debug?: boolean;
  /** Include LearnModeProvider (default: true) */
  includeLearnMode?: boolean;
}
```

### LearnModeProvider

Provides interactive UI hints functionality.

```tsx
import { LearnModeProvider, useLearnMode } from '@netcap/ui/contexts';

// In a component
const { 
  isLearnModeActive,    // boolean - is learn mode enabled?
  toggleLearnMode,      // () => void - toggle learn mode
  currentHint,          // string | null - current hint text
  setCurrentHint,       // (hint: string | null) => void
  currentElementTitle,  // string | null - current element name
  setCurrentElementTitle, // (title: string | null) => void
} = useLearnMode();
```

---

## Hooks

### useNetcapRouter

Framework-agnostic router hook that replaces `useRouter` from Next.js.

```tsx
import { useNetcapRouter } from '@netcap/ui';

function MyComponent() {
  const router = useNetcapRouter();
  
  // Basic navigation
  router.push('/hosts');
  router.replace('/alerts');
  
  // Navigate with query params
  router.navigateTo('/search', { q: 'malware', type: 'connection' });
  
  // Get query parameters
  const searchQuery = router.getQueryParam('q');      // string | undefined
  const allParams = router.getQueryParams();          // Record<string, string>
  
  // Check active path
  const isHostsActive = router.isActive('/hosts');    // boolean
  
  // Access raw values
  console.log(router.pathname);   // '/hosts'
  console.log(router.query);      // { id: '123' }
  console.log(router.isReady);    // true
}
```

### useNetcapApi

Returns a configured API client that respects the provider's `backendUrl`.

```tsx
import { useNetcapApi } from '@netcap/ui';
import useSWR from 'swr';

function MyComponent() {
  const api = useNetcapApi();
  
  // Use with SWR for data fetching
  const { data: status } = useSWR('status', () => api.getStatus());
  const { data: hosts } = useSWR('hosts', () => api.getHostsCount());
  
  // Direct API calls
  const handleUpload = async (file: File) => {
    const response = await api.uploadFile(file);
    console.log('Uploaded:', response.filename);
  };
  
  // Many more methods available...
  // api.getInputFiles()
  // api.getAlerts()
  // api.getRules()
  // api.stopCapture()
  // ... 100+ methods
}
```

### useBackendUrl / useApiBaseUrl

Get the configured backend URL.

```tsx
import { useBackendUrl, useApiBaseUrl } from '@netcap/ui';

function DownloadButton() {
  const backendUrl = useBackendUrl();   // 'http://localhost:8080'
  const apiBaseUrl = useApiBaseUrl();   // 'http://localhost:8080/api'
  
  return (
    <a href={`${apiBaseUrl}/files/download/capture.pcap`}>
      Download PCAP
    </a>
  );
}
```

### useNetcapLink

Get the configured Link component.

```tsx
import { useNetcapLink } from '@netcap/ui';

function Navigation() {
  const Link = useNetcapLink();
  
  return (
    <nav>
      <Link href="/hosts">Hosts</Link>
      <Link href="/connections">Connections</Link>
    </nav>
  );
}
```

---

## Components

### Layout

Main layout component with navigation sidebar.

```tsx
import { Layout } from '@netcap/ui/components';

interface LayoutProps {
  children: React.ReactNode;
  title: string;
  headerAction?: React.ReactNode;
  topPadding?: string | { xs?: string; sm?: string; md?: string; lg?: string };
}

function MyPage() {
  return (
    <Layout 
      title="Network Analysis" 
      headerAction={<Button>Export</Button>}
      topPadding="100px"
    >
      <YourContent />
    </Layout>
  );
}
```

### NetcapLink

Navigation link component using the configured Link.

```tsx
import { NetcapLink } from '@netcap/ui/components';

<NetcapLink href="/hosts">View Hosts</NetcapLink>
<NetcapLink href="/alerts" style={{ color: 'red' }}>Alerts</NetcapLink>
```

### FileSelectorHeader

PCAP file selector for page headers.

```tsx
import { FileSelectorHeader } from '@netcap/ui/components';
import useSWR from 'swr';

function MyPage() {
  const api = useNetcapApi();
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());
  const { data: status } = useSWR('status', () => api.getStatus());
  const [switchingFile, setSwitchingFile] = useState(false);
  
  const handleFileChange = async (path: string) => {
    setSwitchingFile(true);
    await api.setActiveDirectory(path);
    setSwitchingFile(false);
  };
  
  return (
    <Layout 
      title="My Page"
      headerAction={
        <FileSelectorHeader
          inputFiles={inputFiles || []}
          status={status}
          switchingFile={switchingFile}
          onFileChange={handleFileChange}
          learnHint="Select a PCAP file to analyze"
        />
      }
    >
      {/* Page content */}
    </Layout>
  );
}
```

### Syntax Highlighting Components

#### BPFExpressionHighlight

```tsx
import { BPFExpressionHighlight, BPFExpressionBlock } from '@netcap/ui/components';

// Inline highlight
<BPFExpressionHighlight expression="tcp port 443 and host 192.168.1.1" />

// Block display with background
<BPFExpressionBlock expression="tcp port 443 and not src net 10.0.0.0/8" />
```

#### FilterExpressionHighlight

```tsx
import { 
  FilterExpressionHighlight, 
  FilterExpressionBlock, 
  FilterExpressionInline 
} from '@netcap/ui/components';

// Inline (no background)
<FilterExpressionInline expression='SrcIP == "192.168.1.1"' />

// Block (with background)
<FilterExpressionBlock expression='Protocol == "HTTP" && DstPort == 443' />
```

#### RegexHighlight

```tsx
import { RegexHighlight, RegexBlock } from '@netcap/ui/components';

<RegexHighlight pattern="^(GET|POST|PUT|DELETE)\s+" />
<RegexBlock pattern="password[=:]\s*[^\s&]+" />
```

#### SyntaxHighlightedInput

```tsx
import { SyntaxHighlightedInput, SyntaxHighlightedTextArea } from '@netcap/ui/components';

// Single-line input
<SyntaxHighlightedInput
  value={bpfFilter}
  onChange={(e) => setBpfFilter(e.target.value)}
  highlightType="bpf"
/>

// Multi-line textarea
<SyntaxHighlightedTextArea
  value={filterExpression}
  onChange={(e) => setFilterExpression(e.target.value)}
  highlightType="filter"
  rows={4}
/>
```

### Learn Mode Components

```tsx
import { LearnModeToggle, LearnModeOverlay } from '@netcap/ui/components';

// Toggle button (typically in header)
<LearnModeToggle />

// Overlay (typically at root level)
function App() {
  return (
    <LearnModeProvider>
      <LearnModeOverlay />
      <MainContent />
    </LearnModeProvider>
  );
}
```

### Dialog Components

```tsx
import { ConversationModal, ReportIssueDialog } from '@netcap/ui/components';

// View TCP/UDP conversation data
<ConversationModal
  open={showConversation}
  onClose={() => setShowConversation(false)}
  srcIP="192.168.1.100"
  srcPort="54321"
  dstIP="93.184.216.34"
  dstPort="443"
  protocol="TCP"
/>

// Report an issue with a PCAP file
<ReportIssueDialog
  open={showReport}
  onClose={() => setShowReport(false)}
  sessionId="abc123"
/>
```

### Chart Components

```tsx
import { OptimizedPieChart } from '@netcap/ui/components';

<OptimizedPieChart
  data={[
    { name: 'HTTP', value: 1234 },
    { name: 'HTTPS', value: 5678 },
    { name: 'DNS', value: 890 },
  ]}
  nameKey="name"
  valueKey="value"
/>
```

---

## Pages

All page components are complete, ready-to-use views that include data fetching, filtering, sorting, and pagination.

### Available Pages

| Page Component | Description | Route |
|---------------|-------------|-------|
| `DashboardPage` | Overview dashboard with stats | `/` |
| `AlertsPage` | Security alerts and detections | `/alerts` |
| `HostsPage` | Discovered network hosts | `/hosts` |
| `DevicesPage` | Network devices | `/devices` |
| `ConnectionsPage` | TCP/UDP connections | `/connections` |
| `ServicesPage` | Detected services | `/services` |
| `CertificatesPage` | TLS/SSL certificates | `/certificates` |
| `CredentialsPage` | Harvested credentials | `/credentials` |
| `HttpPage` | HTTP requests/responses | `/http` |
| `DomainsPage` | DNS queries and domains | `/domains` |
| `FingerprintsPage` | JA3/JA4 fingerprints | `/fingerprints` |
| `SoftwarePage` | Detected software | `/software` |
| `VulnerabilitiesPage` | CVE vulnerabilities | `/vulnerabilities` |
| `RulesPage` | Detection rule editor | `/rules` |
| `RulesetsPage` | Rule set management | `/rulesets` |
| `InjectPage` | Packet injection rules | `/inject` |
| `PcapsPage` | PCAP file management | `/pcaps` |
| `FilesPage` | Extracted files | `/files` |
| `LogsPage` | Application logs | `/logs` |
| `ErrorsPage` | Processing errors | `/errors` |
| `AuditPage` | Audit record browser | `/audit` |
| `RecordsPage` | Raw record explorer | `/records` |
| `ExplorePage` | Data exploration charts | `/explore` |
| `VisualizePage` | Network visualizations | `/visualize` |
| `ConfigPage` | Application configuration | `/config` |
| `DecodersPage` | Protocol decoder config | `/decoders` |
| `HarvestersPage` | Credential harvester config | `/harvesters` |
| `BPFPage` | BPF filter configuration | `/bpf` |
| `InterfacesPage` | Network interfaces | `/interfaces` |
| `ProbesPage` | Service probe editor | `/probes` |
| `DbsPage` | Database management | `/dbs` |
| `DpiPage` | Deep packet inspection | `/dpi` |
| `AnalyzePage` | Quick analysis page | `/analyze` |

### Usage

```tsx
// pages/alerts.tsx (Next.js)
import { AlertsPage } from '@netcap/ui/pages';

export default function Alerts() {
  return <AlertsPage />;
}
```

```tsx
// With React Router
import { Routes, Route } from 'react-router-dom';
import { 
  DashboardPage, 
  AlertsPage, 
  HostsPage,
  ConnectionsPage 
} from '@netcap/ui/pages';

<Routes>
  <Route path="/" element={<DashboardPage />} />
  <Route path="/alerts" element={<AlertsPage />} />
  <Route path="/hosts" element={<HostsPage />} />
  <Route path="/connections" element={<ConnectionsPage />} />
</Routes>
```

---

## Utility Functions

### formatBytes

Format bytes to human-readable string.

```tsx
import { formatBytes } from '@netcap/ui';

formatBytes(0);           // '0 B'
formatBytes(1024);        // '1 KB'
formatBytes(1536);        // '1.5 KB'
formatBytes(1048576);     // '1 MB'
formatBytes(1073741824);  // '1 GB'
```

### formatTimestamp

Format timestamps (handles seconds, milliseconds, and nanoseconds).

```tsx
import { formatTimestamp } from '@netcap/ui';

formatTimestamp(1700000000);                 // '11/14/2023, 3:13:20 PM'
formatTimestamp(1700000000000);              // Same (milliseconds)
formatTimestamp(1700000000000000000);        // Same (nanoseconds)
formatTimestamp(0);                          // 'N/A'
```

### formatDuration

Format duration in seconds to human-readable string.

```tsx
import { formatDuration } from '@netcap/ui';

formatDuration(0.5);    // '500ms'
formatDuration(5);      // '5.0s'
formatDuration(65);     // '1m 5s'
formatDuration(3665);   // '1h 1m'
```

### Syntax Highlighting Functions

```tsx
import { 
  highlightBPFExpression, 
  highlightFilterExpression, 
  highlightRegexPattern 
} from '@netcap/ui';

// Returns array of tokens for custom rendering
const bpfTokens = highlightBPFExpression('tcp port 443');
// [{ type: 'protocol', value: 'tcp' }, { type: 'keyword', value: 'port' }, ...]

const filterTokens = highlightFilterExpression('SrcIP == "192.168.1.1"');
const regexTokens = highlightRegexPattern('^GET\\s+');
```

### createApi

Create an API client with a specific backend URL.

```tsx
import { createApi } from '@netcap/ui';

// For custom scenarios where you need a standalone API client
const api = createApi('https://my-netcap-server.com');
const status = await api.getStatus();
```

---

## Types Reference

### Core Types

```tsx
import type {
  // Provider types
  NetcapConfig,
  RouterAdapter,
  LinkProps,
  LinkComponent,
  
  // Router types
  NetcapRouter,
  
  // API client type
  NetcapApiClient,
} from '@netcap/ui';
```

### API Response Types

```tsx
import type {
  // Status and processing
  StatusResponse,
  ProcessingStats,
  StatsResponse,
  
  // Files
  FileInfo,
  AuditFileInfo,
  ExtractedFileInfo,
  ExtractedFilesResponse,
  
  // Alerts and rules
  Alert,
  AlertsResponse,
  GroupedAlert,
  GroupedAlertsResponse,
  AlertStatsResponse,
  Rule,
  RulesResponse,
  RuleSet,
  RuleSetsResponse,
  
  // Injection
  InjectionRule,
  InjectionEvent,
  InjectionAction,
  
  // Configuration
  ConfigOption,
  ConfigResponse,
  DecoderInfo,
  DecodersResponse,
  HarvesterInfo,
  HarvestersConfig,
  BPFConfig,
  BPFInfoResponse,
  
  // Data types
  ChartDataPoint,
  ChartDataResponse,
  ProtocolHierarchyResponse,
  ConversationData,
  
  // ... and many more
} from '@netcap/ui';
```

### Component Props Types

```tsx
import type {
  LayoutProps,
  FileSelectorHeaderProps,
} from '@netcap/ui/components';
```

---

## Examples

### Custom Page with API Integration

```tsx
import { Layout, useNetcapApi, useNetcapRouter, formatBytes } from '@netcap/ui';
import useSWR from 'swr';
import { Box, Card, Typography, Button } from '@mui/material';

export function CustomAnalysisPage() {
  const api = useNetcapApi();
  const router = useNetcapRouter();
  
  const { data: status, error } = useSWR('status', () => api.getStatus());
  const { data: stats } = useSWR('stats', () => api.getStats());
  
  if (error) return <div>Failed to load</div>;
  if (!status) return <div>Loading...</div>;
  
  return (
    <Layout title="Custom Analysis">
      <Box sx={{ p: 3 }}>
        <Card sx={{ p: 2 }}>
          <Typography variant="h6">
            {status.isProcessing ? 'Processing...' : 'Ready'}
          </Typography>
          {stats && (
            <Typography>
              Packets processed: {stats.processingStats.packetsProcessed}
            </Typography>
          )}
          <Button 
            onClick={() => router.navigateTo('/hosts')}
            variant="contained"
          >
            View Hosts
          </Button>
        </Card>
      </Box>
    </Layout>
  );
}
```

### Using Syntax Highlighting in Forms

```tsx
import { 
  Layout, 
  SyntaxHighlightedTextArea, 
  BPFExpressionBlock,
  useNetcapApi 
} from '@netcap/ui';
import { useState } from 'react';
import { Box, Button, Paper } from '@mui/material';

export function BPFFilterEditor() {
  const [filter, setFilter] = useState('tcp port 443');
  const [saved, setSaved] = useState('');
  const api = useNetcapApi();
  
  const handleSave = async () => {
    await api.saveBPFConfig({ filter });
    setSaved(filter);
  };
  
  return (
    <Layout title="BPF Filter Editor">
      <Box sx={{ p: 3, display: 'flex', flexDirection: 'column', gap: 2 }}>
        <SyntaxHighlightedTextArea
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          highlightType="bpf"
          rows={3}
          placeholder="Enter BPF filter expression..."
        />
        
        <Button variant="contained" onClick={handleSave}>
          Save Filter
        </Button>
        
        {saved && (
          <Paper sx={{ p: 2 }}>
            <Typography variant="subtitle2">Saved filter:</Typography>
            <BPFExpressionBlock expression={saved} />
          </Paper>
        )}
      </Box>
    </Layout>
  );
}
```

### Integrating with React Router (Full Example)

```tsx
// App.tsx
import { BrowserRouter, Routes, Route, Link, useNavigate, useLocation, useSearchParams } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { NetcapProvider, LearnModeProvider, LearnModeOverlay } from '@netcap/ui';
import { DashboardPage, HostsPage, AlertsPage, ConnectionsPage } from '@netcap/ui/pages';

const theme = createTheme({ palette: { mode: 'dark' } });

function NetcapRouterProvider({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  const config = {
    backendUrl: process.env.REACT_APP_BACKEND_URL || 'http://localhost:8080',
    router: {
      pathname: location.pathname,
      query: Object.fromEntries(searchParams),
      isReady: true,
      push: navigate,
      replace: (path: string) => navigate(path, { replace: true }),
    },
    Link: ({ href, children, ...props }: any) => (
      <Link to={href} {...props}>{children}</Link>
    ),
  };

  return (
    <NetcapProvider config={config}>
      <LearnModeProvider>
        <LearnModeOverlay />
        {children}
      </LearnModeProvider>
    </NetcapProvider>
  );
}

export default function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <BrowserRouter>
        <NetcapRouterProvider>
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/hosts" element={<HostsPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/connections" element={<ConnectionsPage />} />
          </Routes>
        </NetcapRouterProvider>
      </BrowserRouter>
    </ThemeProvider>
  );
}
```

---

## Import Paths

The package supports multiple import paths for optimal tree-shaking:

```tsx
// Main entry - includes everything
import { Layout, useNetcapApi, formatBytes } from '@netcap/ui';

// Specific entry points - better tree-shaking
import { Layout, FileSelectorHeader } from '@netcap/ui/components';
import { DashboardPage, HostsPage } from '@netcap/ui/pages';
import { NetcapProvider } from '@netcap/ui/providers';
import { LearnModeProvider, useLearnMode } from '@netcap/ui/contexts';
import { useNetcapRouter, useNetcapApi } from '@netcap/ui/hooks';
import { formatBytes, formatTimestamp, createApi } from '@netcap/ui/lib';

// Next.js adapter
import { NextjsNetcapProvider } from '@netcap/ui/adapters/nextjs';
```

---

## License

GPL-3.0

---

## Contributing

Contributions are welcome! The source code is located at:
https://github.com/dreadl0ck/netcap/tree/master/cmd/capture/webui/frontend/packages/netcap-ui

