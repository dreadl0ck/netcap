# WebUI Integration for Netcap Try Service

## Overview

The Netcap Try Service now integrates the full webUI from the capture tool, allowing users to:
1. Upload PCAP files via a simple interface
2. View real-time analysis progress
3. Explore results using the same sophisticated UI as the capture tool
4. Browse audit records, logs, and statistics
5. Download results as tar.gz archives

## Architecture

### Session-Based Model

The try service uses a session-based architecture:

```
User uploads PCAP → Session created → Analysis queued → Processing → Results ready
                          ↓
                   Automatically selected for webUI viewing
```

### Components

1. **Try Service Core** (`cmd/try/`)
   - Upload handling
   - Session management
   - Rate limiting
   - Job queue processing
   - Auto-cleanup

2. **WebUI Package** (`cmd/try/webui/`)
   - Embeds capture webUI frontend
   - Adapts webUI API to session model
   - Proxies requests to current session data

3. **Frontend** (copied from `cmd/capture/webui/frontend/out`)
   - Full Next.js static export
   - Material-UI components
   - Audit record viewers
   - Log viewers
   - SSE streaming support

## API Endpoints

### Try Service APIs

- `POST /api/upload` - Upload PCAP file
- `GET /api/try/sessions` - List all sessions
- `GET /api/try/session/{id}` - Select session for viewing
- `GET /api/quota` - Check upload quota
- `GET /api/download/{sessionId}` - Download results
- `GET /health` - Health check

### WebUI APIs (proxied to current session)

- `GET /api/status` - Session status for webUI
- `GET /api/files/audit` - List audit files
- `GET /api/files/logs` - List log files
- `GET /api/audit/{type}/meta` - Audit file metadata
- `GET /api/audit/{type}/stream` - Stream audit records (SSE)
- `GET /api/logs/{name}` - Log file contents

### Static Assets

- `GET /` - WebUI frontend (index.html)
- `GET /_next/*` - Next.js assets
- etc.

## How It Works

### 1. Upload Flow

```javascript
// User uploads via /api/upload
POST /api/upload
  ↓
Create session
  ↓
Set as current session (s.SetCurrentSession(sessionID))
  ↓
Queue for analysis
  ↓
Return sessionID to client
```

### 2. Viewing Flow

Once upload completes and returns a sessionID:

```
Frontend polls /api/status/{sessionID}
  ↓
When status == "completed"
  ↓
User is redirected to main webUI
  ↓
WebUI fetches data via /api/files/audit, /api/audit/{type}/stream, etc.
  ↓
All requests are proxied to the current session's output directory
```

### 3. Multi-Session Support

Users can switch between sessions:

```javascript
// Select a different session
GET /api/try/sessions  // List all
POST /api/try/session/{id}  // Switch to session
  ↓
WebUI now shows data from selected session
```

## Session Auto-Selection

When a file is uploaded, the session is automatically selected for viewing:

```go
// In handleUpload (handlers.go)
s.SetCurrentSession(sessionID)
```

This means the webUI will immediately show data from the newly uploaded file once analysis completes.

## Implementation Details

### Server Integration (`cmd/try/server.go`)

```go
type Server struct {
    webUIServer    *webui.Server
    currentSession string  // Active session for webUI
    // ... other fields
}

// Proxy handlers forward to webUI with current session data
func (s *Server) handleWebUIAuditFiles(w http.ResponseWriter, r *http.Request) {
    session := s.GetCurrentSession()
    if session == nil || session.Status != StatusCompleted {
        respondJSON(w, http.StatusOK, []interface{}{})
        return
    }
    webui.HandleAuditFiles(session.OutputDir)(w, r)
}
```

### WebUI Handlers (`cmd/try/webui/handlers.go`)

The webUI handlers are adapted from the capture webUI but work with a single output directory (the current session's output):

```go
func HandleAuditFiles(outputDir string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // List .ncap.gz files from outputDir
        files, err := listAuditFiles(outputDir)
        respondJSON(w, http.StatusOK, files)
    }
}
```

### Frontend Assets

The frontend is embedded at compile time:

```go
//go:embed frontend/out
//go:embed frontend/out/_next
// ... more patterns
var embeddedAssets embed.FS
```

## User Experience

### Upload Page

When users first visit the service:
1. See upload form with drag-and-drop
2. Select PCAP file (up to 50MB)
3. View quota remaining
4. Click "Upload and Analyze"

### Analysis Progress

During analysis:
1. Status updates via polling
2. Shows "queued" → "processing" → "completed"
3. Progress indicator

### Results Exploration

Once complete:
1. Full webUI interface loads
2. Can browse audit record files
3. Stream and explore records
4. View logs
5. Download complete results

### Session Management

Advanced users can:
1. View all their sessions: `GET /api/try/sessions`
2. Switch between sessions: `POST /api/try/session/{id}`
3. Each session has independent results

## Development

### Frontend Development

For hot-reload development:

```bash
# Terminal 1: Next.js dev server
cd cmd/capture/webui/frontend
npm run dev

# Terminal 2: Try service
# (modify webui/server.go to support -http-assets flag)
net try -http :7070 -http-assets http://localhost:3000
```

### Building

```bash
# Build frontend (if modified)
cd cmd/capture/webui/frontend
npm install
npm run build

# Copy to try service
cd ../../../..
cp -r cmd/capture/webui/frontend/out cmd/try/webui/frontend/

# Build netcap
zeus install
```

## Testing

### Test Upload

```bash
# Start service
net try -http :7070

# Upload file
curl -X POST -F "file=@test.pcap" http://localhost:7070/api/upload
# Returns: {"sessionId":"abc123...","status":"queued"}

# Check status
curl http://localhost:7070/api/status/abc123
# Returns: {"status":"processing"} then {"status":"completed"}
```

### Test WebUI

1. Open browser: `http://localhost:7070`
2. Upload a PCAP file
3. Wait for analysis to complete
4. WebUI should load showing audit files
5. Click on any audit type to view records
6. Check logs tab for analysis logs

### Test Session Switching

```bash
# List sessions
curl http://localhost:7070/api/try/sessions

# Switch to specific session
curl -X POST http://localhost:7070/api/try/session/{sessionId}

# WebUI now shows that session's data
```

## Advantages of This Approach

1. **Reuses Existing UI**: No need to maintain separate frontend
2. **Full Feature Set**: Users get all webUI capabilities
3. **Consistent UX**: Same interface as capture tool
4. **Session Isolation**: Each upload is independent
5. **Multi-Session Support**: Can view past analyses
6. **Easy Maintenance**: Updates to capture webUI automatically benefit try service

## Limitations

1. **Static Assets**: Frontend must be copied/built before compiling
2. **Single Active Session**: WebUI shows one session at a time
3. **No Live Mode**: Try service is file-based only
4. **Memory Usage**: Streaming large audit files uses memory

## Future Enhancements

Possible improvements:
1. Session picker UI in frontend
2. Side-by-side session comparison
3. Persistent session history beyond 1 hour
4. Share session URLs with others
5. API authentication for multi-user support
6. Integration with netcap-dbs-server for enrichment

## Troubleshooting

### Frontend Not Loading

```bash
# Check if assets were copied
ls cmd/try/webui/frontend/out/

# If missing, copy from capture webUI
cp -r cmd/capture/webui/frontend/out cmd/try/webui/frontend/

# Rebuild
zeus install
```

### WebUI Shows No Data

```bash
# Check current session
curl http://localhost:7070/api/status

# If no session, upload a file first
curl -X POST -F "file=@test.pcap" http://localhost:7070/api/upload
```

### Analysis Doesn't Complete

```bash
# Check logs
# In your terminal running `net try`
# Or check the session's output directory

# Verify DPI is enabled (required)
net try -http :7070 -dpi=true
```

## Summary

The webUI integration provides a powerful, familiar interface for exploring PCAP analysis results in the try service. By reusing the capture webUI components and adapting them to a session-based model, users get full audit record exploration capabilities with minimal additional code.

