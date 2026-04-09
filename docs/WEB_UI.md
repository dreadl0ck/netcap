# Netcap Web UI

The Netcap Web UI provides a browser-based interface for exploring packet capture data in real-time. This feature was added to make it easier to browse input files, audit records, and logs without having to use command-line tools.

## Overview

The Web UI consists of two main components:

1. **Backend (Go)**: HTTP server with RESTful API and SSE streaming
2. **Frontend (Next.js)**: Modern React-based UI with Material-UI components

## Quick Start

### Using the Web UI

Start a capture with the `-http` flag to enable the web interface:

```bash
# Process a single PCAP file
net capture -read traffic.pcap -out output -http localhost:8080

# Process multiple PCAP files
net capture -read "*.pcap" -out results -http localhost:8080

# Custom port
net capture -read traffic.pcap -out output -http 0.0.0.0:8888
```

The web interface will be available at the specified address (e.g., `http://localhost:8080`).

### Keep-Alive Behavior

When using the `-http` flag with file-based captures:

1. The web server starts before processing begins
2. You can view progress in the browser as files are processed
3. **After processing completes**, the server continues running
4. You can explore the results at your leisure
5. Press `Ctrl+C` in the terminal to stop the server

This allows you to process files during the day and explore results later without restarting.

## Features

### Dashboard

The main dashboard shows:
- Processing status (running or complete)
- Number of input files processed
- Number of audit record types generated
- Total audit records across all types
- Number of log files created
- Output directory path
- Server start time

### Input Files Browser

View all processed PCAP files with:
- Filename and full path
- File size (human-readable)
- Last modified timestamp

### Audit Records Browser

Browse audit records by type:
- List of all audit record types (TCP, UDP, HTTP, etc.)
- Record counts for each type
- File sizes
- **Streaming viewer**: Click "View Records" to stream records from large files
  - Streams up to 1,000 records at a time
  - Real-time progress updates
  - JSON prettification
  - No memory issues with large files

### Logs Viewer

Access log files:
- List of all log files (netcap.log, collector.log, etc.)
- File sizes and timestamps
- Click to view full log contents
- Syntax highlighting for better readability

## Architecture

### Backend API

The backend provides these RESTful endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Capture status and metadata |
| `/api/files/input` | GET | List input PCAP files |
| `/api/files/audit` | GET | List audit record files |
| `/api/files/logs` | GET | List log files |
| `/api/audit/{type}/meta` | GET | Metadata for an audit record type |
| `/api/audit/{type}/stream` | GET | Stream audit records (SSE) |
| `/api/logs/{name}` | GET | Log file contents |

### Server-Sent Events (SSE)

Audit records are streamed using SSE for efficiency:
- **On-demand parsing**: Files are only opened when requested
- **Pagination support**: `?offset=0&limit=1000` parameters
- **Progress events**: Updates every 100 records
- **Automatic reconnection**: Browser handles network errors
- **Memory efficient**: Only current batch in memory

Example SSE messages:

```
event: record
data: {"Timestamp": 1234567890, "SrcIP": "192.168.1.1", ...}

event: progress
data: {"count": 100}

event: complete
data: {"total": 1000}
```

### Frontend Technology

Built with modern web technologies:
- **Next.js 14**: React framework with static export
- **TypeScript**: Type safety throughout
- **Material-UI 5**: Polished component library
- **SWR**: Efficient data fetching with caching
- **Static Export**: Single-page app embedded in Go binary

## Building

### Prerequisites

- Go 1.21+ (for backend)
- Node.js 18+ and pnpm (for frontend)

### Building the Frontend

```bash
cd cmd/capture/webui/frontend
pnpm install
pnpm run build
```

This creates a static export in `frontend/out/` that gets embedded into the Go binary.

### Using the Build Script

A convenience script is provided:

```bash
# Build frontend only
./cmd/capture/webui/build.sh

# Build frontend and Go binary
./cmd/capture/webui/build.sh --with-go
```

### Embedding in Go

The frontend is embedded using Go's `embed` package:

```go
//go:embed frontend/out
var embeddedAssets embed.FS
```

When compiled, the entire frontend is included in the `net` binary with no external dependencies.

## Development

### Frontend Development

For live reload during development:

```bash
cd cmd/capture/webui/frontend
pnpm run dev
```

The dev server runs on `http://localhost:3000`.

### Using Dev Mode

Point the capture command to your dev server:

```bash
net capture -read traffic.pcap -out output \
  -http localhost:8080 \
  -http-assets http://localhost:3000
```

The `-http-assets` flag tells the server to proxy static files from the dev server instead of using embedded assets.

## Customization

### Changing the Theme

Edit `frontend/src/pages/_app.tsx`:

```typescript
const theme = createTheme({
  palette: {
    mode: 'dark', // or 'light'
    primary: {
      main: '#00bcd4', // cyan
    },
    secondary: {
      main: '#ff4081', // pink
    },
  },
});
```

### Adding New Pages

1. Create a new file in `frontend/src/pages/`
2. Add navigation link in `frontend/src/components/Layout.tsx`
3. Implement the page component
4. Rebuild the frontend

### Adding New API Endpoints

1. Add handler function in `cmd/capture/webui/handlers.go`
2. Register route in `cmd/capture/webui/server.go`
3. Add client method in `frontend/src/lib/api.ts`
4. Use in your component with SWR or direct API call

## Performance Considerations

### Audit Record Streaming

Large audit record files (100K+ records) are handled efficiently:
- **Streaming**: Records sent incrementally via SSE
- **Pagination**: Default limit of 1,000 records per request
- **Decompression**: Gzip files decompressed on-the-fly
- **Memory**: Only current batch kept in memory

### File Counting

File metadata (including record counts) is cached:
- First request may be slow for large files
- Subsequent requests are fast
- Consider pre-computing counts in future versions

## Security Considerations

### Network Binding

By default, the server binds to the specified address:
- `localhost:8080`: Only accessible from local machine
- `0.0.0.0:8080`: Accessible from network (use with caution)
- Consider firewall rules for production use

### CORS

CORS is enabled for all origins by default. This allows:
- Using the dev server during development
- Potential cross-origin requests

For production use, consider restricting CORS origins in `webui/server.go`.

### File Access

The Web UI can only access:
- Input files specified on command line
- Output directory specified with `-out` flag
- No directory traversal protection needed (Go's `filepath.Join` handles this)

### Files Preview Security

When previewing extracted files (especially HTML files from network traffic), several security measures are in place to prevent XSS and other attacks:

#### Frontend Protections

1. **HTML Files Default to Raw View**: HTML files open in "Raw Source" tab by default instead of rendered view, preventing accidental script execution
2. **Strict Iframe Sandboxing**: When viewing HTML in rendered mode, an empty `sandbox=""` attribute is used, which:
   - Blocks all JavaScript execution
   - Prevents form submissions
   - Blocks popups and modals
   - Prevents plugins from running
   - Still allows basic HTML/CSS rendering for visual inspection
3. **Security Warning Banner**: A prominent warning is displayed when viewing HTML files in rendered mode, alerting users to potential risks

#### Backend Security Headers

The backend sets multiple security headers when serving extracted files:

- **X-Content-Type-Options: nosniff**: Prevents MIME type sniffing attacks
- **X-Frame-Options: SAMEORIGIN**: Prevents clickjacking by restricting iframe embedding
- **Content-Security-Policy**: Restrictive policy that blocks scripts and limits resource loading
- **Path Validation**: Ensures requested files are within the designated files directory to prevent directory traversal attacks

#### Best Practices

When working with extracted files from network captures:

1. **Treat all files as potentially malicious**: They may come from compromised or malicious sources
2. **Use raw view for inspection**: The "Raw Source" tab is the safest way to examine HTML content
3. **Be cautious with rendered preview**: Only use rendered view when necessary, and understand the risks
4. **Download with care**: Downloaded files should be scanned with antivirus software before opening
5. **Isolated environment**: Consider running Netcap Web UI in an isolated/sandboxed environment when analyzing untrusted traffic

## Troubleshooting

### Frontend Assets Not Found

If you see "Frontend assets not built" in the browser:

1. Build the frontend: `cd cmd/capture/webui/frontend && pnpm run build`
2. Verify `out/` directory exists with `index.html`
3. Rebuild Go binary: `go build ./cmd`

### Port Already in Use

Error: `address already in use`

Solution: Choose a different port with `-http localhost:8081`

### Browser Can't Connect

Checklist:
- Server actually started (check terminal output)
- Correct URL (check for http:// prefix)
- Firewall not blocking (especially on Windows)
- Browser not caching old version (hard refresh with Ctrl+F5)

### SSE Connection Fails

If streaming doesn't work:
- Check browser console for errors
- Verify file exists in output directory
- Try with a smaller file first
- Check server logs for error messages

## Future Enhancements

Potential improvements for future versions:
- **Real-time updates**: Live streaming during capture
- **Filtering**: Filter audit records by fields
- **Export**: Download filtered results as CSV/JSON
- **Visualization**: Charts and graphs for traffic patterns
- **Search**: Full-text search across audit records
- **Authentication**: Basic auth for network deployments
- **WebSocket**: Bidirectional communication for advanced features

## Files Reference

### Backend (Go)
- `cmd/capture/flags.go`: Command-line flags
- `cmd/capture/main.go`: Integration with capture command
- `cmd/capture/webui/server.go`: HTTP server setup
- `cmd/capture/webui/handlers.go`: API endpoint handlers
- `cmd/capture/webui/audit_reader.go`: Audit record file parsing
- `cmd/capture/webui/embed.go`: Frontend asset embedding

### Frontend (TypeScript/React)
- `frontend/src/components/Layout.tsx`: Main layout with navigation
- `frontend/src/lib/api.ts`: API client and utilities
- `frontend/src/pages/index.tsx`: Dashboard page
- `frontend/src/pages/files.tsx`: Input files browser
- `frontend/src/pages/audit.tsx`: Audit records browser
- `frontend/src/pages/logs.tsx`: Log files viewer
- `frontend/src/pages/_app.tsx`: App wrapper with theme
- `frontend/package.json`: Dependencies and build scripts

## Contributing

When contributing to the Web UI:

1. **Backend changes**: Test with real PCAP files
2. **Frontend changes**: Use dev mode for fast iteration
3. **API changes**: Update both backend and frontend
4. **Documentation**: Update this file and README files

## License

Same as Netcap project (see main LICENSE file).

