# Netcap Try Service

A web service that allows users to upload PCAP files for analysis with automatic rate limiting, session management, and cleanup.

## Features

- **File Upload**: Upload PCAP/PCAPNG files up to 50MB via web interface
- **DPI Analysis**: Deep Packet Inspection is always enabled for all analyses
- **Rate Limiting**: Maximum 2 analyses per IP per hour
- **Storage Limit**: Configurable maximum total storage for uploads and results (default: 10GB)
- **Auto-Cleanup**: Session data and results are automatically removed after 1 hour
- **Download Results**: Download all generated audit records and logs as a tar.gz archive
- **Queue Management**: Jobs are processed one at a time to prevent resource exhaustion
- **Simple Web UI**: Built-in web interface for easy interaction with real-time storage monitoring

## Usage

### Start the Service

```bash
# Start with default settings (port 7070, 10GB storage limit)
# Note: DPI is always enabled for all analyses
net try -http :7070

# Specify custom data directory
net try -http :7070 -data-dir /custom/path

# Set custom storage limit (20GB)
net try -http :7070 -max-storage 21474836480

# Disable storage limit (unlimited)
net try -http :7070 -max-storage 0
```

### Configuration Flags

- `-http` - HTTP server address (required, e.g., `:7070`)
- `-data-dir` - Directory for uploads and results (default: `~/.local/share/netcap-try` for local, `/data/netcap-try` in Docker)
- `-max-file-size` - Maximum upload file size in bytes (default: `52428800` = 50MB)
- `-max-analysis-hour` - Maximum analyses per IP per hour (default: `2`)
- `-session-expiry` - Session expiry time in minutes (default: `60`)
- `-cleanup-interval` - Cleanup check interval in minutes (default: `10`)
- `-max-storage` - Maximum total storage for uploads and results in bytes (default: `10737418240` = 10GB, set to `0` for unlimited)

**Note:** DPI (Deep Packet Inspection) is always enabled for all analyses and is not user-configurable.

## API Endpoints

### Upload File
```http
POST /api/upload
Content-Type: multipart/form-data

file: <pcap/pcapng file>
```

**Response:**
```json
{
  "sessionId": "uuid",
  "status": "queued",
  "message": "File uploaded successfully and queued for analysis",
  "remaining": 1
}
```

### Check Status
```http
GET /api/status/{sessionId}
```

**Response:**
```json
{
  "sessionId": "uuid",
  "ip": "192.168.1.1",
  "uploadTimestamp": "2024-01-15T10:00:00Z",
  "inputFilename": "capture.pcap",
  "status": "completed",
  "packetsTotal": 12345,
  "resultsReady": true
}
```

**Status Values:**
- `queued` - Waiting for processing
- `processing` - Currently being analyzed
- `completed` - Analysis finished, results ready
- `failed` - Analysis failed

### Download Results
```http
GET /api/download/{sessionId}
```

Returns a `tar.gz` archive containing:
- All `.ncap.gz` audit record files
- `netcap.log` (if available)
- `metadata.json` with analysis summary

### Check Quota
```http
GET /api/quota
```

**Response:**
```json
{
  "limit": 2,
  "remaining": 1,
  "allowed": true,
  "storage": {
    "current": 1073741824,
    "max": 10737418240,
    "available": 9663676416,
    "percentUsed": 10.0,
    "unlimited": false
  }
}
```

### Health Check
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": 1705315200,
  "sessions": 3,
  "queueSize": 1
}
```

## Web Interface

Access the web interface by navigating to the server address in a browser (e.g., `http://localhost:7070`).

Features:
- Drag-and-drop or click to upload
- Real-time quota display
- Real-time storage usage monitoring with visual progress bar
- Progress tracking
- One-click download of results
- Automatic upload blocking when storage limit is reached

## Rate Limiting

The service enforces rate limiting based on client IP address:

- **Limit**: 2 analyses per hour (configurable)
- **Tracking**: In-memory, resets when service restarts
- **Response**: HTTP 429 when limit exceeded

## Session Management

Sessions are automatically cleaned up:

- **Expiry**: 1 hour after upload (configurable)
- **Cleanup**: Runs every 10 minutes (configurable)
- **Removal**: Both upload and result files are deleted, freeing up storage space

## Storage Management

The service implements a configurable storage limit to prevent disk exhaustion:

- **Default Limit**: 10GB total for uploads and generated results
- **Upload Blocking**: New uploads are denied when storage limit is exceeded
- **Automatic Recovery**: Storage is freed when the cleanup routine removes expired sessions
- **Real-Time Monitoring**: Web UI displays current storage usage with visual indicators
- **Estimation**: System estimates ~3x file size needed (uploaded PCAP + analysis results)
- **Configurable**: Set via `-max-storage` flag, or set to `0` for unlimited storage

**Storage States:**
- **Normal** (< 75%): Blue indicator, uploads allowed
- **Warning** (75-90%): Orange indicator, uploads still allowed
- **Critical** (90-95%): Red indicator, uploads still allowed
- **Full** (≥ 95%): Red indicator, uploads blocked until cleanup frees space

## Docker Deployment

See `docker/try/README.md` for Docker deployment instructions.

## Security Considerations

When deploying in production:

1. **Reverse Proxy**: Use nginx or similar for HTTPS/SSL
2. **File Validation**: The service validates file types and sizes, but additional validation may be needed
3. **Rate Limiting**: Default rate limits may need adjustment based on your use case
4. **Resource Limits**: Consider setting Docker resource limits
5. **Network Isolation**: Run in isolated network environment if handling sensitive data

## Example Usage

```bash
# Upload a file
curl -X POST -F "file=@capture.pcap" http://localhost:7070/api/upload

# Response: {"sessionId":"abc-123","status":"queued",...}

# Check status
curl http://localhost:7070/api/status/abc-123

# Download results (when completed)
curl -O http://localhost:7070/api/download/abc-123
```

## Troubleshooting

### Upload Fails

- Check file size (must be ≤ 50MB)
- Verify file format (.pcap or .pcapng)
- Check rate limit quota
- Check storage limit - uploads are blocked when storage reaches 95% of limit
- Wait for cleanup routine to free space (runs every 10 minutes)

### Analysis Fails

- Check server logs for detailed error messages
- Ensure PCAP file is valid and not corrupted
- Verify sufficient disk space

### Quota Issues

- Quota resets after 1 hour from last upload
- Each IP is tracked independently
- Quota information resets when service restarts

## Development

To modify the web UI, edit the HTML in `server.go` or create a separate frontend using the API endpoints.

## License

See the main NETCAP repository for license information.

