<!-- bda1c4f8-b299-478b-9aa2-509395c5564f ac97a594-8f99-4be0-8e83-1b6503bb475c -->
# Merge Local and Service Mode Server Implementations

## Overview

Refactor to use a single unified Server in the `cmd/capture/webui` package that handles both local mode (unrestricted, no sessions) and service mode (with sessions, uploads, rate limiting). Service mode will execute analysis in-process using isolated collector instances instead of spawning subprocesses.

## Phase 1: Extend webui.Server with Service Mode Capabilities

### 1.1 Add Service-Specific Fields to webui.Server

Extend `cmd/capture/webui/server.go` Server struct to include:

- `isServiceMode bool` - flag to differentiate modes
- `sessionManager *SessionManager` - nil in local mode
- `serviceConfig *ServiceConfig` - nil in local mode
- `jobQueue chan *AnalysisJob` - nil in local mode
- `shutdownChan chan struct{}` - for graceful shutdown
- `wg sync.WaitGroup` - track background workers

### 1.2 Move Service Types to webui Package

Copy from `cmd/capture/service/`:

- `session.go` → `cmd/capture/webui/session.go`
- `config.go` → `cmd/capture/webui/service_config.go` (rename to avoid conflict)
- `AnalysisJob` struct from `server.go`

## Phase 2: Implement In-Process Job Execution

### 2.1 Create In-Process Analysis Function

In `cmd/capture/webui/server.go`, add new method:

```go
func (s *Server) runAnalysisInProcess(job *AnalysisJob) error
```

This replaces `cmd/capture/service/server.go:runAnalysis()` which uses `exec.Command`. Instead:

1. Create isolated `collector.New()` instance with job-specific config
2. Call `c.CollectPcap()` or `c.CollectPcapNG()` directly
3. Capture errors and update session status
4. Track processing stats and timing
5. Properly cleanup resources on completion/error

Key differences from subprocess approach:

- Direct library calls instead of `exec.Command(executable, args...)`
- Reuse flag parsing logic from `cmd/capture/main.go` to build collector Config
- Run in goroutine per job for isolation
- Use context for cancellation

### 2.2 Add Job Queue Worker

In `cmd/capture/webui/server.go`, add:

```go
func (s *Server) processJobs()
```

Only active in service mode, processes jobs from `jobQueue` channel sequentially.

## Phase 3: Migrate Service Mode Handlers

### 3.1 Copy Service-Specific Handlers

From `cmd/capture/service/handlers.go` to `cmd/capture/webui/service_handlers.go`:

- `handleUpload` - file upload endpoint
- `handleStatus` - session status polling
- `handleListSessions` - list all sessions
- `handleSessionSelect` - select active session
- `handleQuota` - rate limit info
- `handleReportIssue` - issue reporting
- `handleHealth` - health check
- `handleViewSession` - shareable session links

### 3.2 Add Conditional Logic to Existing Handlers

Update handlers in `cmd/capture/webui/handlers.go` and `shared_handlers.go`:

- Check `s.isServiceMode` flag
- If service mode: use session-based routing (current session or from query param)
- If local mode: use existing file-based routing
- Apply restrictions only in service mode (rate limiting, storage checks)

Example pattern:

```go
func (s *Server) handleSomeEndpoint(w http.ResponseWriter, r *http.Request) {
    if s.isServiceMode {
        // Service mode: get session from s.currentSession or query param
        session, ok := s.sessionManager.GetSession(sessionID)
        // ... use session.OutputDir
    } else {
        // Local mode: use s.outDir directly
    }
}
```

## Phase 4: Unified Server Constructor and Startup

### 4.1 Update NewServer Constructor

Modify `cmd/capture/webui/server.go:NewServer()` signature:

```go
func NewServer(addr, outDir string, inputFiles []string, assetsPath string, 
               debugLogging bool, dpiConfigured bool, 
               isServiceMode bool, serviceConfig *ServiceConfig) *Server
```

Initialize service-specific components only if `isServiceMode == true`:

- Create `SessionManager` if service mode
- Initialize `jobQueue` channel if service mode
- Setup cleanup routines if service mode

### 4.2 Update Server.Start() Method

Enhance `cmd/capture/webui/server.go:Start()`:

- Register all handlers (local + service)
- Service-only handlers return 404 or error in local mode
- Start job processor goroutine only in service mode
- Start cleanup routine only in service mode

### 4.3 Update Server.Stop() Method

Enhance graceful shutdown to handle:

- Stop job queue (if service mode)
- Wait for active jobs to complete (with timeout)
- Cleanup sessions (if service mode)

## Phase 5: Update Entry Points

### 5.1 Modify cmd/capture/main.go

Around lines 574-599 where webUI server is initialized:

```go
if *flagHTTP != "" {
    // Determine if this is service mode (already checked earlier)
    // Create unified server
    webUIServer = webui.NewServer(
        *flagHTTP, 
        initialOutDir, 
        inputFiles, 
        *flagHTTPAssets, 
        *flagDebug, 
        *flagDPI,
        false, // isServiceMode = false for local mode
        nil,   // no service config in local mode
    )
    // ... existing code
}
```

### 5.2 Modify cmd/capture/service_mode.go

Replace service.NewServer with webui.NewServer:

```go
func runServiceMode() {
    // ... existing config building ...
    
    // Create service configuration
    serviceConfig := &webui.ServiceConfig{
        // ... from flags ...
    }
    
    // Create unified server in service mode
    server := webui.NewServer(
        *flagHTTP,
        config.DataDir,
        nil, // no input files in service mode
        "",  // no custom assets path
        false, // debug logging
        *flagDPI,
        true, // isServiceMode = true
        serviceConfig,
    )
    
    // ... existing startup and signal handling ...
}
```

## Phase 6: Cleanup and Migration

### 6.1 Copy Platform-Specific System Info

Copy system info functions from `cmd/capture/service/system*.go` to `cmd/capture/webui/`:

- Merge with existing `webui/system*.go` files
- Deduplicate any overlapping functionality

### 6.2 Copy BPF Utilities

Copy `cmd/capture/service/bpf.go` functions into `cmd/capture/webui/bpf.go` or integrate into existing BPF handling.

### 6.3 Update Frontend API Detection

In `cmd/capture/webui/frontend/src/lib/api.ts` and related pages:

- Ensure `isServiceMode` flag is properly detected from `/api/status`
- Local mode shows no upload UI, no sessions, no quotas
- Service mode shows full session management UI

### 6.4 Remove Old Service Package

After all migrations are complete and tested:

- Delete `cmd/capture/service/` directory
- Update imports across codebase

## Phase 7: Testing and Validation

### 7.1 Test Local Mode

- `net capture -read file.pcap -out results/ -http localhost:8080`
- Verify no sessions created
- Verify direct file processing works
- Verify webUI shows results correctly
- Verify no rate limiting or restrictions

### 7.2 Test Service Mode

- `net capture --service -http localhost:7070`
- Verify file uploads work
- Verify session creation and tracking
- Verify in-process analysis executes correctly
- Verify rate limiting applies
- Verify storage limits enforced
- Verify all service features preserved

### 7.3 Test In-Process Execution

- Verify collector state isolation between jobs
- Verify proper resource cleanup
- Verify error handling and logging
- Verify processing stats match subprocess behavior
- Test concurrent job queuing

## Key Implementation Details

### Collector Config Building

Extract the collector configuration logic from `cmd/capture/main.go` (lines ~704-800) into a helper function:

```go
func buildCollectorConfig(job *AnalysisJob, baseConfig Config) collector.Config
```

This ensures service mode jobs use the same configuration as local mode.

### Session-to-Output Directory Mapping

In service mode:

- Each session has `OutputDir` = `{DataDir}/results/{SessionID}/`
- Handlers check `isServiceMode` and route to appropriate directory
- Local mode continues using `outDir` directly

### Rate Limiting Strategy

Only check rate limits in service mode:

```go
if s.isServiceMode && !s.sessionManager.CheckRateLimit(ip) {
    // reject request
}
```

### Storage Management

Only enforce storage limits in service mode:

```go
if s.isServiceMode && totalSize > s.serviceConfig.MaxStorageBytes {
    // reject upload
}
```

## Files Modified

- `cmd/capture/webui/server.go` - unified server
- `cmd/capture/webui/session.go` - NEW (copied from service)
- `cmd/capture/webui/service_config.go` - NEW (copied from service)
- `cmd/capture/webui/service_handlers.go` - NEW (migrated handlers)
- `cmd/capture/webui/handlers.go` - add conditional logic
- `cmd/capture/webui/shared_handlers.go` - add conditional logic
- `cmd/capture/webui/types.go` - add service types
- `cmd/capture/webui/system*.go` - merge system info
- `cmd/capture/main.go` - update server initialization
- `cmd/capture/service_mode.go` - update to use webui.Server
- `cmd/capture/flags.go` - ensure all flags accessible

## Files Deleted

- `cmd/capture/service/` - entire directory after migration

## Benefits

1. **Single Source of Truth**: One server implementation to maintain
2. **Feature Parity**: Both modes benefit from improvements
3. **Better Performance**: In-process execution eliminates subprocess overhead
4. **Simpler Testing**: Test one unified server instead of two separate ones
5. **Easier Debugging**: No subprocess boundary to cross
6. **Flexible Configuration**: Service mode becomes a configuration option, not a separate architecture