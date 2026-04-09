# Netcap Service Mode and Session Concept

## Overview

**Service Mode** (previously called "try mode") is a special operational mode of the `net capture` command that transforms Netcap into a web-based multi-user service for analyzing PCAP files. Instead of processing a single file locally, it runs as an HTTP server where users can upload PCAP files, queue them for analysis, and view results through a web UI.

## Architecture

### Command Structure

```bash
# Standard capture mode
net capture -read traffic.pcap -out results/

# Service mode
net capture --service -http localhost:7070
```

### Service Mode Flags

The following flags control service mode behavior:

| Flag | Description | Default |
|------|-------------|---------|
| `--service` | Enable service mode for multi-file upload and analysis | false |
| `--service-data-dir` | Directory for uploads and results | auto-detect |
| `--service-max-file-size` | Maximum upload file size in bytes | 100MB (104857600) |
| `--service-max-per-hour` | Maximum analyses per IP per hour | 10 |
| `--service-expiry` | Session expiry time in minutes | 60 |
| `--service-cleanup` | Cleanup check interval in minutes | 10 |
| `--service-max-storage` | Maximum total storage in bytes | 10GB (0 = unlimited) |

### Usage Examples

```bash
# Start service mode on port 7070
net capture --service -http localhost:7070

# With custom data directory
net capture --service -http localhost:7070 --service-data-dir /var/netcap/data

# With custom limits
net capture --service -http localhost:7070 \
  --service-max-file-size 104857600 \
  --service-max-per-hour 5 \
  --service-expiry 120 \
  --service-max-storage 21474836480

# With DPI enabled
net capture --service -http localhost:7070 -dpi
```

## Session Concept

A **session** represents a complete analysis lifecycle for a single uploaded PCAP file. Each session is tracked from upload through analysis to result viewing.

### Session Structure

```go
type SessionInfo struct {
    SessionID       string        // Unique identifier (16 hex chars)
    IP              string        // Client IP address
    UploadTimestamp time.Time     // When file was uploaded
    InputFile       string        // Path to uploaded PCAP file
    InputFilename   string        // Original filename
    InputFileSize   int64         // File size in bytes
    OutputDir       string        // Results directory
    Status          SessionStatus // Current status
    ErrorMessage    string        // Error details (if failed)
    StartTime       time.Time     // Processing start time
    CompletionTime  time.Time     // Processing completion time
    PacketsTotal    int64         // Total packets processed
    ResultsReady    bool          // Whether results are viewable
    IsPreloaded     bool          // System demo PCAP (never expires)
    BPFFilter       string        // BPF filter applied
    IncludeDecoders string        // Decoders included
    ExcludeDecoders string        // Decoders excluded
}
```

### Session Status States

Sessions transition through four states:

1. **queued** - File uploaded, waiting for processing
2. **processing** - Currently being analyzed
3. **completed** - Analysis finished successfully
4. **failed** - Analysis encountered an error

```
┌─────────┐
│ queued  │
└────┬────┘
     │
     v
┌────────────┐      ┌────────┐
│ processing │─────>│ failed │
└─────┬──────┘      └────────┘
      │
      v
┌───────────┐
│ completed │
└───────────┘
```

### Session Lifecycle

1. **Upload Phase**
   - User uploads PCAP file via web UI
   - File validated (size, type, magic bytes)
   - Rate limit checked for client IP
   - Storage limit checked
   - Unique session ID generated
   - Session directories created

2. **Queue Phase**
   - Session registered in SessionManager
   - Analysis job added to queue
   - Status: `queued`
   - Shareable URL generated

3. **Processing Phase**
   - Job picked up by worker
   - Status updated to `processing`
   - Netcap subprocess spawned
   - Progress tracked

4. **Completion Phase**
   - Analysis finishes
   - Status updated to `completed` or `failed`
   - Results marked ready
   - User can view/download results

5. **Expiry Phase**
   - After configured expiry time (default: 60 minutes)
   - Session removed from manager
   - Files deleted from disk
   - (Preloaded sessions never expire)

## Key Components

### 1. SessionManager

The `SessionManager` is the core component that tracks all active sessions across all users.

**Responsibilities:**
- Track all sessions by session ID
- Implement rate limiting per IP address
- Manage session expiry and cleanup
- Associate sessions with client IPs for security
- Update session status throughout lifecycle

**Key Methods:**

```go
// Check if IP can perform another analysis
func (sm *SessionManager) CheckRateLimit(ip string) (allowed bool, remaining int)

// Register a new session
func (sm *SessionManager) AddSession(session *SessionInfo)

// Retrieve session by ID
func (sm *SessionManager) GetSession(sessionID string) (*SessionInfo, bool)

// Update session status
func (sm *SessionManager) UpdateSessionStatus(sessionID string, status SessionStatus, errorMsg string)

// Remove expired sessions
func (sm *SessionManager) CleanupExpiredSessions() []string

// Get all sessions for an IP
func (sm *SessionManager) GetSessionsForIP(ip string) []*SessionInfo
```

### 2. Rate Limiting

Service mode implements per-IP rate limiting to prevent abuse.

**IPTracker Structure:**
```go
type IPTracker struct {
    IP            string      // Client IP
    AnalysisTimes []time.Time // Timestamps of analyses
    Sessions      []string    // Associated session IDs
}
```

**How it works:**
1. Each upload attempt checks `CheckRateLimit()` for the client IP
2. Counts analyses in the last hour
3. Rejects if limit exceeded
4. Returns remaining quota
5. Old analysis timestamps automatically expire

**Example:**
- IP `192.168.1.100` uploads file at 10:00 AM
- Limit: 10 analyses per hour
- At 10:30 AM: 9 remaining
- At 11:00 AM: Analysis from 10:00 AM expires
- At 11:01 AM: 10 remaining again

### 3. Server Architecture

The service mode server uses a job queue architecture for sequential processing.

**Components:**

```go
type Server struct {
    addr           string           // HTTP server address
    config         *Config          // Service configuration
    enableDPI      bool             // DPI enabled flag
    httpServer     *http.Server     // HTTP server
    sessionManager *SessionManager  // Session tracker
    jobQueue       chan *AnalysisJob // Job queue (buffered)
    shutdownChan   chan struct{}    // Shutdown signal
    wg             sync.WaitGroup   // Worker coordination
    currentSession string           // Active session for UI
    mu             sync.RWMutex     // Lock for current session
}
```

**Job Processing:**
- Single worker goroutine processes jobs sequentially
- Prevents resource exhaustion from parallel analysis
- Jobs queued in buffered channel (capacity: 100)
- Netcap spawned as subprocess for each job
- Status updated throughout processing

**Background Tasks:**
1. **Job Processor** - Processes analysis jobs one at a time
2. **Cleanup Routine** - Periodically removes expired sessions
3. **HTTP Server** - Serves web UI and API endpoints

### 4. Analysis Workflow

When a PCAP file is uploaded:

```
┌──────────┐
│  Upload  │
└────┬─────┘
     │
     v
┌─────────────────┐
│   Validation    │ ← Size, type, magic bytes
└────┬────────────┘
     │
     v
┌─────────────────┐
│  Rate Limit     │ ← Check IP quota
└────┬────────────┘
     │
     v
┌─────────────────┐
│ Storage Check   │ ← Ensure capacity
└────┬────────────┘
     │
     v
┌─────────────────┐
│ Create Session  │ ← Generate ID, create dirs
└────┬────────────┘
     │
     v
┌─────────────────┐
│  Queue Job      │ ← Add to processing queue
└────┬────────────┘
     │
     v
┌─────────────────┐
│   Processing    │ ← Spawn netcap subprocess
└────┬────────────┘
     │
     v
┌─────────────────┐
│  Completion     │ ← Mark results ready
└─────────────────┘
```

**Job Structure:**
```go
type AnalysisJob struct {
    SessionID       string
    InputFile       string  // Path to uploaded PCAP
    OutputDir       string  // Results directory
    EnableDPI       bool    // DPI flag
    BPFFilter       string  // BPF filter to apply
    IncludeDecoders string  // Decoders to include
    ExcludeDecoders string  // Decoders to exclude
}
```

**Processing Details:**
```go
// Netcap command built for each job
args := []string{
    "capture",
    "-read", job.InputFile,
    "-out", job.OutputDir,
    "-quiet",
    "-http", "", // Disable web UI server
}

if job.EnableDPI {
    args = append(args, "-dpi")
}

if job.BPFFilter != "" {
    args = append(args, "-bpf", job.BPFFilter)
}

if job.IncludeDecoders != "" {
    args = append(args, "-include", job.IncludeDecoders)
}

if job.ExcludeDecoders != "" {
    args = append(args, "-exclude", job.ExcludeDecoders)
}
```

## Configuration

### Service Config Structure

```go
type Config struct {
    DataDir         string // Base data directory
    MaxFileSize     int64  // Max upload size (bytes)
    MaxAnalysisHour int    // Max analyses per IP per hour
    SessionExpiry   int    // Session lifetime (minutes)
    CleanupInterval int    // Cleanup frequency (minutes)
    MaxStorageBytes int64  // Total storage cap (bytes)
}
```

### Default Configuration

```go
DataDir:         getDefaultDataDir()  // Auto-detect
MaxFileSize:     100 * 1024 * 1024    // 100MB
MaxAnalysisHour: 10                   // 10 per hour
SessionExpiry:   60                   // 60 minutes
CleanupInterval: 10                   // 10 minutes
MaxStorageBytes: 10 * 1024 * 1024 * 1024 // 10GB
```

### Data Directory Detection

The data directory is automatically determined based on environment:

**Docker/Container:**
```
/data/netcap-service
```

**Local Development:**
```
~/.local/share/netcap-service
```

**Fallback:**
```
./netcap-service-data
```

## Directory Structure

```
<data-dir>/
├── uploads/                    # Uploaded PCAP files
│   ├── <sessionID1>/
│   │   └── input.pcap
│   ├── <sessionID2>/
│   │   └── input.pcapng
│   └── ...
├── results/                    # Analysis results
│   ├── <sessionID1>/
│   │   ├── Connection.ncap.gz
│   │   ├── DNS.ncap.gz
│   │   ├── HTTP.ncap.gz
│   │   ├── IPProfile.ncap.gz
│   │   ├── TCP.ncap.gz
│   │   ├── UDP.ncap.gz
│   │   ├── netcap.log
│   │   └── ... (other audit records)
│   ├── <sessionID2>/
│   │   └── ... (analysis artifacts)
│   └── ...
└── pcaps/                      # Optional: preloaded demo files
    ├── demo1.pcap
    ├── demo2.pcapng
    └── ...
```

### File Organization

**Per-Session Structure:**
- Each session gets unique directories for uploads and results
- Session ID is 16 hex characters (e.g., `7f3a9c8b4e2d1f0a`)
- Uploaded file saved as `input.pcap` or `input.pcapng`
- Results include all standard Netcap audit records
- Logs captured for debugging

## Session Cleanup

Sessions automatically expire to prevent storage exhaustion.

### Cleanup Process

1. **Trigger:** Background goroutine runs every `CleanupInterval` minutes
2. **Expiry Check:** Sessions older than `SessionExpiry` minutes are marked
3. **Exception:** Preloaded demo sessions never expire (`IsPreloaded = true`)
4. **File Removal:** Both upload and result directories deleted
5. **Manager Update:** Session removed from active tracking
6. **IP Tracker Update:** Old analysis timestamps removed

### Cleanup Logic

```go
func (sm *SessionManager) CleanupExpiredSessions() []string {
    expiryTime := time.Now().Add(-time.Duration(sm.sessionExpiryMin) * time.Minute)
    expiredSessions := []string{}

    // Find expired sessions
    for sessionID, session := range sm.sessions {
        // Skip preloaded system pcaps
        if session.IsPreloaded {
            continue
        }
        
        if session.UploadTimestamp.Before(expiryTime) {
            expiredSessions = append(expiredSessions, sessionID)
            delete(sm.sessions, sessionID)
        }
    }

    // Clean up IP trackers
    for ip, tracker := range sm.ipTrackers {
        // Remove expired analysis times (older than expiry)
        validTimes := []time.Time{}
        for _, t := range tracker.AnalysisTimes {
            if t.After(expiryTime) {
                validTimes = append(validTimes, t)
            }
        }
        tracker.AnalysisTimes = validTimes

        // Remove expired session references
        // ... (filter out expired sessions)

        // Remove IP tracker if no recent activity
        if len(tracker.AnalysisTimes) == 0 {
            delete(sm.ipTrackers, ip)
        }
    }

    return expiredSessions
}
```

### Storage Management

Before accepting uploads, the server checks storage capacity:

```go
func (s *Server) CheckStorageLimit(estimatedNeed int64) (allowed bool, current int64, max int64) {
    // MaxStorageBytes of 0 means unlimited
    if s.config.MaxStorageBytes == 0 {
        return true, 0, 0
    }

    // Calculate current usage (recursively measure data directory)
    currentUsage, err := calculateDirSize(s.config.DataDir)
    if err != nil {
        log.Printf("[Service] Error calculating storage usage: %v", err)
        return false, 0, s.config.MaxStorageBytes
    }

    // Check if new upload would exceed limit
    // Estimate: uploaded file + 2x for analysis results
    estimatedTotal := currentUsage + estimatedNeed
    allowed = estimatedTotal <= s.config.MaxStorageBytes

    return allowed, currentUsage, s.config.MaxStorageBytes
}
```

## API Endpoints

### Session Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/upload` | POST | Upload PCAP file, create session |
| `/api/status/{sessionID}` | GET | Get session status for polling |
| `/api/try/sessions` | GET | List all sessions for client IP |
| `/api/try/session/{sessionID}` | POST | Select active session for viewing |
| `/api/quota` | GET | Get rate limit quota for client IP |
| `/api/download/{sessionID}` | GET | Download results as tar.gz |
| `/view/{sessionID}` | GET | View session results (shareable link) |

### Upload Response

```json
{
  "sessionId": "7f3a9c8b4e2d1f0a",
  "status": "queued",
  "message": "File uploaded successfully and queued for analysis",
  "remaining": 9,
  "shareUrl": "http://localhost:7070/view/7f3a9c8b4e2d1f0a"
}
```

### Status Response

```json
{
  "sessionId": "7f3a9c8b4e2d1f0a",
  "ip": "192.168.1.100",
  "uploadTimestamp": "2025-10-31T10:00:00Z",
  "inputFile": "/data/netcap-service/uploads/7f3a9c8b4e2d1f0a/input.pcap",
  "inputFilename": "traffic.pcap",
  "inputFileSize": 5242880,
  "outputDir": "/data/netcap-service/results/7f3a9c8b4e2d1f0a",
  "status": "completed",
  "startTime": "2025-10-31T10:00:05Z",
  "completionTime": "2025-10-31T10:02:30Z",
  "packetsTotal": 12345,
  "resultsReady": true,
  "bpfFilter": "port 80 or port 443",
  "includeDecoders": "",
  "excludeDecoders": ""
}
```

### Quota Response

```json
{
  "allowed": true,
  "remaining": 9,
  "limit": 10,
  "resetTime": "2025-10-31T11:00:00Z"
}
```

## Special Features

### 1. Shareable Links

Each session gets a unique, shareable URL:

```
http://localhost:7070/view/7f3a9c8b4e2d1f0a
```

**Features:**
- No authentication required (session ID is the credential)
- Direct link to analysis results
- Can be shared via email, chat, etc.
- Expires with session

**Use Cases:**
- Share analysis results with colleagues
- Include in reports or tickets
- Collaborative debugging

### 2. Preloaded PCAPs

Demo/example PCAPs can be pre-loaded at server startup.

**Setup:**
1. Place PCAP files in `<data-dir>/pcaps/` directory
2. Server automatically detects and processes them on startup
3. Sessions created with `IsPreloaded = true`
4. Never expire (exempt from cleanup)

**Benefits:**
- Instant examples for new users
- Tutorial/training content
- Demo functionality without requiring uploads

### 3. Multi-Session Support

Users can have multiple active sessions simultaneously:

- Upload multiple files without waiting
- Switch between different analyses
- View history of recent analyses
- Each session tracked independently

**UI Behavior:**
- "Your Recent Analyses" shows all sessions for client IP
- Click to switch active session
- Current session highlighted
- Results displayed for active session

### 4. BPF Filter & Decoder Config

Sessions preserve the configuration used during analysis:

```go
session := &SessionInfo{
    // ... other fields
    BPFFilter:       "port 80 or port 443",
    IncludeDecoders: "TCP,UDP,HTTP,TLS",
    ExcludeDecoders: "ARP,ICMP",
}
```

**Benefits:**
- Reproducible analysis
- See what filters were applied
- Understand decoder selection
- Compare different configurations

## Security Considerations

### 1. IP-Based Rate Limiting

Prevents abuse by limiting analyses per IP:
- Default: 10 per hour
- Configurable via `--service-max-per-hour`
- Protects server resources
- Fair usage across clients

### 2. Storage Limits

Prevents disk exhaustion:
- Total storage cap (default: 10GB)
- Per-file size limit (default: 100MB)
- Automatic cleanup of expired sessions
- Pre-upload capacity check

### 3. File Validation

Multiple validation layers:
- File extension check (`.pcap`, `.pcapng`)
- Magic byte verification (PCAP headers)
- Size limit enforcement
- Multipart form validation

### 4. Session Isolation

Each session isolated from others:
- Unique session ID (cryptographically random)
- Separate directories
- IP-association tracking
- No cross-session data access

### 5. Input Sanitization

Analysis runs in isolated subprocess:
- No shell interpretation of filenames
- Quoted arguments
- Dedicated output directories
- Resource limits via OS

## Use Cases

### 1. Education

**Scenario:** Provide PCAP analysis service to students

**Benefits:**
- No local installation required
- Browser-based access
- Shareable results for homework
- Rate limiting prevents abuse
- Storage limits control costs

**Example:**
```bash
# Start service on university server
net capture --service -http 0.0.0.0:7070 \
  --service-max-per-hour 3 \
  --service-expiry 120
```

### 2. Collaboration

**Scenario:** Team analyzing network issues

**Benefits:**
- Upload once, share link with team
- Multiple team members view same results
- No file transfers needed
- Results available until expiry
- Standardized analysis configuration

**Example:**
```bash
# Analyst uploads PCAP
curl -F "file=@suspicious.pcap" http://team-server:7070/api/upload

# Response includes shareUrl
# Share: http://team-server:7070/view/abc123...

# Team members access without re-upload
```

### 3. Demo/Testing

**Scenario:** Quickly analyze PCAPs without local setup

**Benefits:**
- Web UI for exploration
- Pre-loaded examples
- No software installation
- Cross-platform (browser-based)
- Instant feedback

**Example:**
```bash
# Setup demo server with examples
mkdir -p /data/netcap-service/pcaps
cp examples/*.pcap /data/netcap-service/pcaps/

net capture --service -http 0.0.0.0:7070 -dpi
```

### 4. Multi-User Environments

**Scenario:** Central analysis service for SOC team

**Benefits:**
- Single server instance
- Per-analyst session tracking
- Fair resource allocation (rate limiting)
- Centralized result storage
- Audit trail (IP tracking)

**Example:**
```bash
# Production deployment
net capture --service -http 0.0.0.0:7070 \
  --service-data-dir /mnt/analysis \
  --service-max-file-size 524288000 \
  --service-max-per-hour 20 \
  --service-expiry 480 \
  --service-max-storage 107374182400 \
  -dpi
```

## Docker Deployment

### Using Pre-built Image

```bash
# Pull image
docker pull dreadl0ck/netcap-service:latest

# Run service
docker run -d \
  -p 7070:7070 \
  -v netcap-service-data:/data \
  -e NC_MAX_FILE_SIZE=104857600 \
  -e NC_MAX_ANALYSIS_HOUR=10 \
  -e NC_SESSION_EXPIRY=60 \
  dreadl0ck/netcap-service:latest
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NC_HTTP` | HTTP server address | `0.0.0.0:7070` |
| `NC_DATA_DIR` | Data directory | `/data/netcap-service` |
| `NC_DPI` | Enable DPI | `true` |
| `NC_MAX_FILE_SIZE` | Max upload size | `104857600` (100MB) |
| `NC_MAX_ANALYSIS_HOUR` | Max analyses per hour | `10` |
| `NC_SESSION_EXPIRY` | Session lifetime (min) | `60` |
| `NC_CLEANUP_INTERVAL` | Cleanup interval (min) | `10` |

### Docker Compose

```yaml
version: '3.8'

services:
  netcap-service:
    image: dreadl0ck/netcap-service:latest
    ports:
      - "7070:7070"
    volumes:
      - netcap-data:/data
    environment:
      - NC_HTTP=0.0.0.0:7070
      - NC_DATA_DIR=/data/netcap-service
      - NC_DPI=true
      - NC_MAX_FILE_SIZE=104857600
      - NC_MAX_ANALYSIS_HOUR=10
      - NC_SESSION_EXPIRY=60
    restart: unless-stopped

volumes:
  netcap-data:
```

## Monitoring and Debugging

### Health Check Endpoint

```bash
curl http://localhost:7070/health
```

Response:
```json
{
  "status": "healthy",
  "uptime": "2h15m30s",
  "activeSessions": 3,
  "queuedJobs": 1
}
```

### Logs

Service mode logs include:
- Session creation/completion
- Rate limit checks
- Storage checks
- Analysis progress
- Cleanup operations
- Error details

**Example Log Output:**
```
[Service] Starting HTTP server on 0.0.0.0:7070
[Service] Data directory: /data/netcap-service
[Service] Session 7f3a9c8b4e2d1f0a created for 192.168.1.100 (file: traffic.pcap, size: 5242880 bytes)
[Service] Starting analysis for session 7f3a9c8b4e2d1f0a
[SessionManager] Updating session 7f3a9c8b4e2d1f0a status: queued -> processing
[Service] Analysis completed for session 7f3a9c8b4e2d1f0a (duration: 2m25s)
[SessionManager] Session 7f3a9c8b4e2d1f0a marked as completed and ready
[Service] Cleanup: removed 2 expired sessions
```

### Metrics

Key metrics to monitor:
- Active sessions count
- Queue depth
- Storage usage
- Analysis duration
- Rate limit hits
- Error rate
- Cleanup frequency

## Troubleshooting

### Common Issues

#### 1. Storage Limit Exceeded

**Symptom:** Upload rejected with 507 Insufficient Storage

**Solutions:**
- Increase `--service-max-storage`
- Decrease `--service-expiry` (more frequent cleanup)
- Manually clean old sessions
- Set `--service-max-storage 0` for unlimited

#### 2. Rate Limit Hit

**Symptom:** Upload rejected with 429 Too Many Requests

**Solutions:**
- Wait for analysis timestamps to expire (1 hour)
- Increase `--service-max-per-hour`
- Use different IP (if testing)
- Check `/api/quota` for reset time

#### 3. Analysis Stuck in Processing

**Symptom:** Session status never changes from "processing"

**Possible Causes:**
- Large PCAP file (may take time)
- Netcap subprocess crashed
- Resource exhaustion

**Debug Steps:**
1. Check server logs for errors
2. Verify netcap subprocess running: `ps aux | grep netcap`
3. Check system resources: `top`, `df -h`
4. Review session-specific logs in results directory

#### 4. Session Not Found

**Symptom:** 404 error when accessing session

**Possible Causes:**
- Session expired and cleaned up
- Invalid session ID
- Session from different server instance

**Solutions:**
- Re-upload file (if expired)
- Verify session ID correctness
- Check session list: `/api/try/sessions`

#### 5. File Upload Fails

**Symptom:** Error during upload

**Checks:**
- File size within limit
- Valid PCAP file (magic bytes)
- Storage capacity available
- Network connection stable
- Correct endpoint (`/api/upload`)

## Best Practices

### For Administrators

1. **Set Appropriate Limits**
   - Base on expected usage patterns
   - Consider storage capacity
   - Balance security vs usability

2. **Monitor Storage**
   - Set alerts for storage usage
   - Adjust expiry time if needed
   - Consider log rotation

3. **Secure Deployment**
   - Use HTTPS in production (reverse proxy)
   - Consider authentication layer
   - Limit network access (firewall)
   - Monitor for abuse

4. **Resource Planning**
   - Sequential processing limits throughput
   - Plan for peak usage
   - Consider scaling with multiple instances
   - Monitor analysis duration

### For Users

1. **File Preparation**
   - Compress large PCAPs before upload
   - Filter unnecessary traffic
   - Split very large captures
   - Use descriptive filenames

2. **Session Management**
   - Save important results before expiry
   - Note shareable URLs immediately
   - Download results if needed long-term
   - Clean up unneeded sessions

3. **Efficient Usage**
   - Use BPF filters to reduce processing
   - Exclude unnecessary decoders
   - Avoid duplicate uploads
   - Check quota before uploading

## Future Enhancements

Potential improvements for future releases:

1. **Authentication & Authorization**
   - User accounts
   - API keys
   - Role-based access control
   - Session ownership

2. **Advanced Rate Limiting**
   - Per-user quotas (not just IP)
   - Different tiers/plans
   - Burst allowance
   - Priority queues

3. **Result Caching**
   - Deduplicate identical PCAPs
   - Hash-based lookup
   - Shared results

4. **Distributed Processing**
   - Multiple worker nodes
   - Load balancing
   - Parallel analysis
   - Horizontal scaling

5. **Enhanced Monitoring**
   - Prometheus metrics
   - Grafana dashboards
   - Alert system
   - Usage analytics

6. **Configuration Profiles**
   - Saved analysis configs
   - Per-user preferences
   - Organization templates
   - Quick presets

7. **Notification System**
   - Email on completion
   - Webhook callbacks
   - WebSocket updates
   - Mobile alerts

## Conclusion

Service mode transforms Netcap into a powerful, multi-user web service for PCAP analysis. The session concept provides:

- **Isolation:** Each analysis is independent and secure
- **Tracking:** Full lifecycle management from upload to expiry
- **Resource Control:** Rate limiting and storage management
- **Collaboration:** Shareable links and multi-session support
- **Usability:** Web-based interface, no installation needed

The architecture balances performance (sequential processing), security (rate limits, validation), and usability (shareable results, preloaded demos), making it suitable for education, collaboration, and production deployments.

