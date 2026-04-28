# Frontend Tech Stack & Setup

The Netcap Web UI is a single-page application that provides a browser-based interface for exploring packet capture data. It communicates with the Go backend exclusively over a REST API — there are no server-rendered pages, no WebSocket connections, and no server-side state in the frontend layer.

## Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Build tool | [Vite](https://vite.dev/) | 6.x |
| UI framework | [React](https://react.dev/) | 19.x |
| Routing | [React Router](https://reactrouter.com/) | 7.x |
| Component library | [MUI (Material UI)](https://mui.com/) | 7.x |
| CSS-in-JS | [Emotion](https://emotion.sh/) | 11.x |
| Data fetching | [SWR](https://swr.vercel.app/) | 2.x |
| Charts | [ECharts](https://echarts.apache.org/) | 6.x |
| Code highlighting | [react-syntax-highlighter](https://github.com/react-syntax-highlighter/react-syntax-highlighter) | 16.x |
| Language | TypeScript | 5.x |
| Package manager | pnpm | 9.x |
| Test runner | [Vitest](https://vitest.dev/) | 3.x |
| Test utilities | Testing Library | 16.x |

## Project Structure

The frontend is a pnpm monorepo with two packages: the root app (a thin shell that wires up routing and providers) and `netcap-ui` (the library containing all UI logic).

```
cmd/capture/webui/frontend/
├── index.html                    # Vite entry point (SPA shell with dark-mode CSS)
├── vite.config.ts                # Vite build & dev server config
├── vitest.config.ts              # Test runner config
├── vitest.setup.ts               # Test setup (mocks for matchMedia, IntersectionObserver)
├── tsconfig.json                 # TypeScript config
├── package.json                  # Root app dependencies & scripts
├── pnpm-workspace.yaml           # Monorepo workspace (references packages/*)
├── .env.local                    # Local env overrides (VITE_BACKEND_URL)
├── public/                       # Static assets (copied as-is to dist/)
│   ├── logo.png
│   └── static/echarts/           # ECharts map data and chart themes
├── src/
│   ├── main.tsx                  # App bootstrap (theme, providers, router, drop zone)
│   ├── routes.tsx                # All 33 route definitions with React.lazy()
│   ├── vite-env.d.ts             # Vite type declarations
│   └── __tests__/                # Test files
├── dist/                         # Build output (embedded into the Go binary)
└── packages/netcap-ui/           # Reusable component library (see below)
```

### `packages/netcap-ui` — Component Library

A framework-agnostic React component library built with [tsup](https://tsup.egoist.dev/). It exports ESM and CJS bundles with TypeScript declarations. The library does not import from any router or framework directly — it uses an adapter pattern (see [Router adapter pattern](#router-adapter-pattern)).

```
packages/netcap-ui/
├── src/
│   ├── adapters/
│   │   ├── react-router.tsx      # React Router adapter (used by the app)
│   │   └── nextjs.tsx            # Next.js adapter (kept for external consumers)
│   ├── components/               # Shared UI components (see listing below)
│   ├── pages/                    # 33 page components (one per route)
│   ├── contexts/                 # React context providers
│   │   ├── LearnModeContext.tsx   # Educational hints system (useLearnMode)
│   │   └── CommunityIDFilterContext.tsx  # Flow filtering (useCommunityIDFilter)
│   ├── hooks/                    # Custom React hooks
│   │   ├── useNetcapApi.ts       # API client bound to provider config
│   │   ├── useNetcapRouter.ts    # Framework-agnostic router access
│   │   ├── useTableKeyboardNavigation.ts  # TAB/ENTER keyboard shortcuts
│   │   └── useViewMode.ts        # List/grid view toggle
│   ├── lib/                      # Utilities
│   │   ├── api.ts                # REST API client (all endpoints, ~2200 lines)
│   │   ├── tableSearch.ts        # Client-side search/filter logic
│   │   ├── filterSyntaxHighlight.ts   # Tokenizer for filter expressions
│   │   ├── bpfSyntaxHighlight.ts      # Tokenizer for BPF expressions
│   │   └── regexSyntaxHighlight.ts    # Tokenizer for regex patterns
│   └── providers/
│       └── NetcapProvider.tsx     # Config provider (backend URL, router, Link)
├── tsup.config.ts                # Library build config (ESM + CJS + DTS)
└── package.json
```

### Components

| Component | Description |
|-----------|-------------|
| `Layout` | App shell — sidebar navigation, toolbar, file selector |
| `ConnectionOverlay` | Full-screen overlay shown when backend is unreachable |
| `SearchInput` | Smart search input with autocomplete |
| `SyntaxHighlightedInput` | Text input with live syntax highlighting |
| `BPFExpressionHighlight` | BPF filter syntax highlighting (inline and block) |
| `FilterExpressionHighlight` | Audit filter expression highlighting |
| `RegexHighlight` | Regex pattern highlighting |
| `OptimizedPieChart` | ECharts pie chart with lazy loading |
| `StatBox` / `StatBoxGrid` | Statistics display cards |
| `ConversationModal` | TCP stream conversation viewer |
| `NetcapLink` | Framework-agnostic navigation link |
| `FileSelectorHeader` | File/session selector dropdown |
| `LearnModeToggle` | Toggle for educational hints |
| `LearnModeOverlay` | Displays learn-mode hints on hover |
| `CommunityIDChip` | Visual chip for Community ID flow identifiers |
| `CommunityIDFilterBar` | Filter bar for Community ID filtering |
| `ReportIssueDialog` | Bug report submission dialog |

## Prerequisites

- **Node.js** 18+
- **pnpm** 9+ (`corepack enable && corepack prepare pnpm@9 --activate`)

## Development

### First-time setup

```bash
cd cmd/capture/webui/frontend
pnpm install
```

### Dev server

```bash
pnpm dev
```

This starts two processes in parallel via `concurrently`:
1. **tsup** in watch mode — rebuilds the `netcap-ui` library on every source change
2. **Vite dev server** — serves the app at `http://localhost:5173` with hot module replacement

The Vite dev server proxies `/api/*` requests to `http://localhost:8080` (configured in `vite.config.ts`), so you need the Go backend running:

```bash
# In another terminal, from the repo root:
net capture -read some.pcap -out output -http localhost:8080

# Or with hot reload via air:
air
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_BACKEND_URL` | `http://localhost:8080` | Backend API URL. Set in `.env.local` for local dev. Statically replaced by Vite at build time. |

The backend URL resolution order at runtime is:
1. `window.__BACKEND_URL__` (for embedded/custom deployment scenarios)
2. `VITE_BACKEND_URL` (baked in at build time)
3. `http://localhost:8080` (fallback)

## Building

### Build the frontend

```bash
cd cmd/capture/webui/frontend
pnpm build
```

This runs two steps:
1. Builds the `netcap-ui` library via tsup
2. Builds the app via `vite build` — output goes to `frontend/dist/`

### Build the Go binary with embedded frontend

```bash
# From the repo root:
go build -o net ./cmd/
```

The Go binary embeds everything in `frontend/dist/` via `//go:embed all:frontend/dist`. The frontend must be built before compiling Go. No Node.js needed at runtime.

### Preview a production build locally

```bash
pnpm preview
```

Serves the `dist/` directory at `http://localhost:4173`.

## Testing

```bash
pnpm test              # Run once
pnpm test:watch        # Watch mode
pnpm test:coverage     # With coverage report
```

Tests use Vitest with jsdom and `globals: true` (so `describe`/`it`/`expect` are available without imports). Test files live in `src/__tests__/`.

## Architecture

### How the pieces fit together

```
┌───────────────────────────────────────────┐
│  Go Binary                                │
│  ┌─────────────────────────────────────┐  │
│  │  HTTP Server (webui/server.go)      │  │
│  │  ├── /api/*   → REST handlers       │  │
│  │  ├── /view/*  → session view (svc)  │  │
│  │  ├── /health  → health check (svc)  │  │
│  │  └── /*       → SPA fallback        │  │
│  │               ↓                     │  │
│  │  ┌───────────────────────────┐      │  │
│  │  │  Embedded frontend/dist/  │      │  │
│  │  │  (index.html + assets/)   │      │  │
│  │  └───────────────────────────┘      │  │
│  └─────────────────────────────────────┘  │
│  Middleware: gzip → CORS → mux            │
└───────────────────────────────────────────┘

Browser loads index.html
  → React app boots
  → React Router handles /alerts, /hosts, etc.
  → SWR fetches data from /api/*
```

### SPA fallback

The Go server implements SPA fallback routing in `embed.go`. Go's `ServeMux` matches longer prefixes first, so `/api/*`, `/view/*`, and `/health` are routed to their Go handlers before the catch-all `/`:

- Requests with a file extension (`.js`, `.css`, `.png`, etc.) → served directly from `dist/`
- Requests without an extension (`/alerts`, `/hosts/`) → serve `index.html`
- React Router then matches the URL client-side to the correct page component

### Backend middleware

All HTTP responses pass through two middleware layers (see `server.go`):

- **Gzip**: Compresses responses when the client sends `Accept-Encoding: gzip`. Skips SSE streams.
- **CORS**: Sets `Access-Control-Allow-Origin: *` and allows `GET`, `POST`, `PUT`, `PATCH`, `DELETE` with `Content-Type` header. This enables the Vite dev server (port 5173) to call the Go backend (port 8080) during development.

### Service mode

When the Go backend runs with `--service`, additional endpoints are registered:

| Endpoint | Description |
|----------|-------------|
| `/api/quota` | Rate limit and storage quota info |
| `/api/try/sessions` | List analysis sessions for the client IP |
| `/api/try/session/` | Select/view a specific session |
| `/api/status/` | Session-specific status polling |
| `/view/` | Shareable session view links |
| `/health` | Health check |

Service mode adds a job queue for PCAP analysis, per-IP rate limiting, session expiry with cleanup, and storage quota tracking. The frontend's PCAPs page (`/pcaps`) adapts its UI when it detects service mode.

### Data fetching

All API calls go through the `api.ts` client. Components use SWR for caching and automatic refresh:

```tsx
const api = useNetcapApi();
const { data, error } = useSWR('hosts', () => api.getHosts(), {
  refreshInterval: 5000,
});
```

The `useNetcapApi()` hook returns an API client bound to the backend URL configured in `NetcapProvider`. The `api` singleton exported from `lib/api.ts` is also available for use outside of React components.

### State management

- **Server state**: SWR handles caching, deduplication, revalidation, and polling
- **Global UI state**: React Context — `LearnModeContext` (educational hints), `CommunityIDFilterContext` (flow filtering)
- **Local state**: `useState` for component-specific UI state
- No Redux or Zustand

### Router adapter pattern

The `netcap-ui` library defines a `RouterAdapter` interface in `NetcapProvider.tsx`:

```typescript
interface RouterAdapter {
  pathname: string;
  query: Record<string, string | string[] | undefined>;
  isReady: boolean;
  push: (path: string) => void | Promise<boolean>;
  replace?: (path: string) => void | Promise<boolean>;
}
```

Each adapter implements this interface for a specific framework. The app uses `ReactRouterNetcapProvider` from `adapters/react-router.tsx`, which wires up `useNavigate()`, `useLocation()`, and `useSearchParams()`. A `nextjs.tsx` adapter is also available for consumers that use Next.js.

All navigation within components goes through `useNetcapRouter()` or `<NetcapLink>`, keeping pages framework-agnostic.

### Styling

- **MUI 7** dark theme — primary: `#00bcd4` (cyan), secondary: `#ff4081` (pink), background: `#121212`
- **Emotion** CSS-in-JS via MUI's `sx` prop and styled components
- Self-hosted **Roboto** (weights: 300, 400, 500, 700) and **Roboto Mono** (400, 700) — no external font requests
- No Tailwind, no CSS modules
- Inline critical CSS in `index.html` prevents a flash of white on page load

### Code splitting

All 33 page components are lazy-loaded via `React.lazy()` in `routes.tsx`. Vite splits them into separate chunks with content-hashed filenames. The hashed chunks are served with `Cache-Control: immutable` for aggressive long-term caching.

### Global features (main.tsx)

The root `main.tsx` provides two app-wide behaviors beyond routing and theming:

- **Connection overlay**: Polls `/api/status` on mount and every 10 seconds. If the backend is unreachable, a full-screen overlay with "Connecting to NETCAP..." is shown. Retries every 1 second until connection is restored.
- **Global drag-and-drop upload**: A drop zone wraps the entire app. Dragging `.pcap`, `.pcapng`, or `.cap` files anywhere on the page triggers an upload overlay. After successful upload, the SWR cache is invalidated and the user is navigated to `/pcaps`.

## Pages

| Route | Page Component | Description |
|-------|---------------|-------------|
| `/` | DashboardPage | Status, stats, file management |
| `/alerts` | AlertsPage | Security alerts and notifications |
| `/analyze` | AnalyzePage | PCAP upload and analysis |
| `/audit` | AuditPage | Generic audit record browser |
| `/bpf` | BPFPage | Berkeley Packet Filter builder |
| `/certificates` | CertificatesPage | TLS certificate viewer |
| `/config` | ConfigPage | Capture configuration |
| `/connections` | ConnectionsPage | TCP/UDP conversations |
| `/credentials` | CredentialsPage | Extracted credentials |
| `/dbs` | DbsPage | Database management |
| `/decoders` | DecodersPage | Decoder selection |
| `/devices` | DevicesPage | Network devices |
| `/domains` | DomainsPage | DNS domains |
| `/dpi` | DpiPage | Deep packet inspection settings |
| `/errors` | ErrorsPage | Error logs |
| `/explore` | ExplorePage | Data explorer |
| `/files` | FilesPage | Extracted files viewer |
| `/fingerprints` | FingerprintsPage | TLS fingerprints (JA4, JA4S, JA4T) |
| `/harvesters` | HarvestersPage | Harvester configuration |
| `/hosts` | HostsPage | IP host profiles |
| `/http` | HttpPage | HTTP requests and responses |
| `/inject` | InjectPage | Packet injection rules |
| `/interfaces` | InterfacesPage | Network interfaces |
| `/logs` | LogsPage | Application logs |
| `/pcaps` | PcapsPage | PCAP file and session management |
| `/probes` | ProbesPage | Service probes |
| `/records` | RecordsPage | Record browser |
| `/rules` | RulesPage | Detection rules |
| `/rulesets` | RulesetsPage | Rule set management |
| `/services` | ServicesPage | Detected services |
| `/software` | SoftwarePage | Software identification |
| `/visualize` | VisualizePage | Charts and visualizations |
| `/vulnerabilities` | VulnerabilitiesPage | Vulnerability scanner |

## Adding a new page

1. Create the page component in `packages/netcap-ui/src/pages/MyPage.tsx`
2. Export it from `packages/netcap-ui/src/pages/index.ts`
3. Add a lazy import and `<Route>` entry in `src/routes.tsx`:
   ```tsx
   const MyPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.MyPage })));
   // inside <Routes>:
   <Route path="/my-page" element={<MyPage />} />
   ```
4. Add a navigation entry in `packages/netcap-ui/src/components/Layout.tsx`

## Adding a new API endpoint

1. Add the Go handler in the appropriate `*_handlers.go` file under `cmd/capture/webui/`
2. Register the route in `cmd/capture/webui/server.go` (before the catch-all `/` handler on line 654)
3. Add the client method in `packages/netcap-ui/src/lib/api.ts`
4. Export any new types from `packages/netcap-ui/src/lib/index.ts`
5. Use it in your page component:
   ```tsx
   const api = useNetcapApi();
   const { data } = useSWR('my-data', () => api.getMyData());
   ```

## Caching strategy

The Go server sets cache headers based on asset type (see `cacheControlMiddleware` in `embed.go`):

| Asset type | Cache-Control | Rationale |
|-----------|--------------|-----------|
| `/assets/*` (hashed chunks) | `public, max-age=31536000, immutable` | Content hash in filename — never changes |
| `.js`, `.css`, fonts | `public, max-age=604800` | May change on rebuild |
| Images | `public, max-age=604800` | Rarely change |
| `index.html` | `public, max-age=3600, must-revalidate` | Must pick up new chunk references |
