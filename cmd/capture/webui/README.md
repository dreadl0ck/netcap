# Netcap Web UI

A web-based user interface for exploring Netcap packet capture data in real-time.

For comprehensive documentation of the frontend tech stack, architecture, and development workflow, see [docs/frontend.md](../../../docs/frontend.md).

## Quick Start

Start a capture with the `-http` flag to enable the web interface:

```bash
# Process a PCAP file with web UI
net capture -read traffic.pcap -out output -http localhost:8080

# Process multiple files
net capture -read "*.pcap" -out output -http localhost:8080
```

The web UI will be available at `http://localhost:8080`. After processing completes, the server continues running so you can explore the results. Press `Ctrl+C` to stop.

## Building

```bash
# Build the frontend (requires Node.js 18+ and pnpm)
cd frontend
pnpm install
pnpm build

# Then build the Go binary (from repo root)
go build -o net ./cmd/
```

The frontend is built with Vite and output to `frontend/dist/`, which is embedded into the Go binary via `//go:embed`.

## Development

```bash
# Start the frontend dev server with hot reload
cd frontend
pnpm dev

# In another terminal, start the Go backend
net capture -read traffic.pcap -out output -http localhost:8080
```

The Vite dev server runs at `http://localhost:5173` and proxies `/api/*` to the Go backend at `localhost:8080`.

## Architecture

- **Backend**: Go HTTP server with REST API, gzip compression, and CORS support
- **Frontend**: React 19 SPA with Vite, React Router 7, MUI 7, and SWR
- **Embedding**: Frontend `dist/` is embedded in the Go binary with SPA fallback routing

## API Endpoints

The backend exposes 80+ REST endpoints. Key categories:

- `/api/status` — Capture status and metadata
- `/api/files/*` — Input files, audit files, logs
- `/api/hosts`, `/api/connections`, `/api/services` — Network data
- `/api/certificates`, `/api/fingerprints` — TLS analysis
- `/api/rules`, `/api/alerts` — Detection and alerting
- `/api/chart/*`, `/api/visualize/*` — Charting data

See `server.go` for the complete route list.
