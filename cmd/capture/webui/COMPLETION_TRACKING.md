# File Completion Tracking

The Web UI now tracks and displays the completion status of each input file during multi-file processing.

## Features

### 1. Backend Tracking

The server tracks which files have completed processing:

```go
completedFiles  map[string]bool   // Tracks which files have completed processing
```

**Tracking Logic:**
- When starting to process file N, mark file N-1 as completed
- When all processing finishes, mark the last file as completed
- Thread-safe with mutex protection

### 2. API Enhancement

**`FileInfo` includes completion status:**
```json
{
  "name": "capture.pcap",
  "path": "/path/to/capture.pcap",
  "size": 1024567,
  "modifiedTime": 1698345678,
  "isCompleted": true
}
```

### 3. Frontend Sorting

Files are sorted automatically:
1. **Completed files first** (ready to view)
2. **Processing files last** (still being processed)
3. Within each group, alphabetically by name

### 4. Visual Indicators

**Completed Files:**
- ✅ Full opacity
- Green checkmark icon (if active)
- Clickable/hoverable
- Eye icon button enabled

**Processing Files:**
- ⏳ Reduced opacity (60%)
- Hourglass icon
- "(processing...)" label
- NOT clickable
- Eye icon button disabled with tooltip "Processing not complete"

### 5. Restricted Viewing

You can only view audit records for completed files:
- **Backend**: `/api/set-directory` returns 400 if file not completed
- **Frontend**: View button is disabled for incomplete files
- **Tooltip feedback**: Shows "Processing not complete" on hover

## Usage Example

```bash
./bin/net capture \
  -read file1.pcap \
  -read file2.pcap \
  -read file3.pcap \
  -out /tmp/analysis \
  -http localhost:8080
```

### During Processing

**Files Page displays:**

```
✅ file1.pcap (1.2 MB)        [View] ← Completed, clickable
⏳ file2.pcap (processing...) (500 KB) [🚫 View] ← Processing, disabled
⏳ file3.pcap (processing...) (750 KB) [🚫 View] ← Processing, disabled
```

### After file2.pcap Completes

```
✅ file1.pcap (1.2 MB)        [View] ← Can view
✅ file2.pcap (500 KB)        [View] ← Just completed, can view
⏳ file3.pcap (processing...) (750 KB) [🚫 View] ← Still processing
```

### All Processing Complete

```
✅ file1.pcap (1.2 MB) [View]
✅ file2.pcap (500 KB) [View]
✅ file3.pcap (750 KB) [View]
```

All files can now be viewed!

## API Behavior

### GET /api/files/input

Returns all files with completion status:

```json
[
  {
    "name": "file1.pcap",
    "path": "/path/to/file1.pcap",
    "size": 1258291,
    "modifiedTime": 1698345600,
    "isCompleted": true
  },
  {
    "name": "file2.pcap",
    "path": "/path/to/file2.pcap",
    "size": 512000,
    "modifiedTime": 1698345650,
    "isCompleted": false
  }
]
```

### POST /api/set-directory

**Request:**
```json
{
  "inputFile": "/path/to/file2.pcap"
}
```

**Response (if complete):**
```json
{
  "success": true,
  "outputDir": "/tmp/analysis/file2.pcap",
  "activeInputFile": "/path/to/file2.pcap"
}
```

**Response (if not complete):**
```
HTTP 400 Bad Request
File processing not yet complete
```

## Terminal Logs

Watch for these log messages:

```
[WebUI] File marked as completed: /path/to/file1.pcap
[WebUI] File marked as completed: /path/to/file2.pcap
[WebUI] File marked as completed: /path/to/file3.pcap
```

When trying to view incomplete file:
```
[WebUI] POST /api/set-directory
HTTP 400: File processing not yet complete
```

## Benefits

1. **Clear Status**: Users always know which files are ready to view
2. **No Errors**: Can't accidentally try to view incomplete audit records
3. **Prioritized**: Completed files shown first for immediate access
4. **Live Updates**: Status updates as processing progresses
5. **User-Friendly**: Visual feedback with icons and tooltips

## Implementation Details

### Marking Completion

**In main.go loop:**
```go
for fileIdx, inputFile := range inputFiles {
    // Start processing file N
    
    // Mark previous file (N-1) as completed
    if webUIServer != nil && fileIdx > 0 {
        webUIServer.MarkFileCompleted(inputFiles[fileIdx-1])
    }
    
    // Process current file...
}

// After loop, mark last file completed
if webUIServer != nil && len(inputFiles) > 0 {
    webUIServer.MarkFileCompleted(inputFiles[len(inputFiles)-1])
}
```

### Frontend Sorting

```typescript
const sortedFiles = files ? [...files].sort((a, b) => {
  // Completed files come first
  if (a.isCompleted && !b.isCompleted) return -1;
  if (!a.isCompleted && b.isCompleted) return 1;
  // Within same completion status, sort by name
  return a.name.localeCompare(b.name);
}) : [];
```

This ensures a consistent, predictable display order that helps users quickly find completed files.

