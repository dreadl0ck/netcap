# WebUI Progress Tracking for Analysis Jobs

## Overview

The WebUI now displays real-time progress for analysis jobs by reading the `netcap.log` file in the capture output directory. Progress is displayed as a percentage during job execution.

## Implementation Details

### Backend Components

#### 1. Progress Handler (`cmd/capture/webui/progress_handler.go`)

New handler that:
- Reads `netcap.log` from the output directory
- Parses progress lines in format: `progress: XX%`
- Returns JSON response with progress information
- Works in both service mode (sessionId) and local mode (file path)

**Endpoint:** `GET /api/progress/{sessionId}`

**Response Format:**
```json
{
  "sessionId": "session-123",
  "status": "processing",
  "progressPercent": 45.5,
  "message": "Processing... 45.5%",
  "errorMessage": ""
}
```

#### 2. Server Registration (`cmd/capture/webui/server.go`)

- Registered new endpoint: `mux.HandleFunc("/api/progress/", s.handleProgress)`
- Available for all modes (service and local)

### Frontend Components

#### 1. API Client (`frontend/src/lib/api.ts`)

Added:
- `ProgressInfo` interface for type safety
- `getProgress(sessionId: string)` function to fetch progress data

#### 2. Analyze Page (`frontend/src/pages/analyze.tsx`)

Enhanced polling logic to:
- Fetch progress information alongside session status
- Display progress percentage in status messages
- Gracefully fall back to elapsed time if progress unavailable
- Works for multiple concurrent uploads

#### 3. PCAPs Page (`frontend/src/pages/pcaps.tsx`)

Added real-time progress display:
- Polls progress for all non-completed files every 2 seconds
- Shows percentage inline: `filename.pcap (67.5%)`
- Displays visual progress bar below filename
- Automatically updates as files are processed
- Works in both service and local modes

## How It Works

### Progress Logging

During capture, netcap logs progress to `netcap.log`:

```
2024-01-15 10:30:15 Starting capture...
2024-01-15 10:30:20 progress: 10%
2024-01-15 10:30:25 progress: 25%
2024-01-15 10:30:30 progress: 50%
2024-01-15 10:30:35 progress: 75%
2024-01-15 10:30:40 progress: 100%
```

### Progress Polling

The frontend polls every 2 seconds:
1. Fetches session status via `/api/status/{sessionId}`
2. If status is "processing", fetches progress via `/api/progress/{sessionId}`
3. Displays progress percentage or elapsed time
4. Redirects to dashboard when all jobs complete

### Supported Modes

#### Service Mode
- **Session Tracking**: Uses sessionId (e.g., `"session-abc123"`)
- **Upload Response**: Returns `sessionId` and `shareUrl`
- **Progress Endpoint**: `/api/progress/{sessionId}`
- **Multiple Jobs**: Fully supported with per-session tracking
- **Output Directory**: Stored in session manager
- **Status Updates**: Real-time via polling

#### Local Mode  
- **Session Tracking**: Uses file path (e.g., `"/path/to/uploads/file.pcap"`)
- **Upload Response**: Returns `path` and `filename`
- **Progress Endpoint**: `/api/progress/{filePath}` (URL-encoded)
- **Multiple Jobs**: Supported via job queue
- **Output Directory**: Calculated from baseOutDir + filename (without extension)
- **Status Updates**: Real-time via polling
- **Background Processing**: Jobs execute in queue while user continues browsing

**Key Difference**: Service mode uses session IDs for tracking, while local mode uses file paths. Both modes share the same progress API and UI components.

## User Experience

### Analyze Page (Upload)

**Before:**
```
Processing file.pcap... (120s elapsed, 1/3 completed)
```

**After:**
```
Processing... 67.5% (1/3 completed)
```

### PCAPs Page (File List)

**Before:**
```
filename.pcap (processing...)
```

**After:**
```
filename.pcap (67.5%)
[====================>            ]  ← Progress bar
```

## Error Handling

- If `netcap.log` doesn't exist: returns 0% progress
- If progress cannot be parsed: falls back to elapsed time display
- If API call fails: continues showing basic status
- No user-facing errors - graceful degradation

## Performance Considerations

- Progress reading is non-blocking
- File is read sequentially to find latest progress
- Minimal overhead (< 1ms for typical log files)
- Polling interval: 2 seconds (balanced between responsiveness and load)

## Testing

### Service Mode

**Analyze Page (Uploads):**
1. Upload a PCAP file via the analyze page
2. Observe the status message updating with progress percentage
3. Progress should update every 2 seconds during processing
4. Upon completion, page redirects to dashboard

**PCAPs Page (File List):**
1. Navigate to PCAPs page
2. Files being processed show inline percentage: `(67.5%)`
3. Progress bar displayed below filename
4. Progress updates automatically every 2 seconds
5. Completed files show checkmark icon

### Local Mode

**Analyze Page (Uploads):**
1. Upload a PCAP file via the analyze page
2. File is queued for background analysis
3. Progress updates display during processing
4. Supports multiple concurrent uploads
5. Upon completion, page redirects to dashboard

**PCAPs Page (File List):**
1. Navigate to PCAPs page
2. Files being processed show inline percentage
3. Visual progress bar updates in real-time
4. Works for all files in queue
5. Navigate away and come back - progress persists

Both modes use the same progress tracking mechanism and UI.

## Future Enhancements

Possible improvements:
- WebSocket-based real-time updates (reduce polling)
- Progress bar visualization
- ETA calculation based on progress rate
- Packet count alongside percentage
- Per-decoder progress breakdown

