# Session Persistence Implementation

## Overview

Sessions now persist across server restarts by saving session metadata to disk and restoring it on startup. This ensures that analysis results remain accessible even after the backend is recompiled or restarted.

## Implementation Details

### 1. Session Metadata Storage

Each session now has a `session.json` file in its results directory containing:
- Session ID
- User IP address
- Input file path and metadata
- Processing status and timestamps
- Error information (if any)
- BPF filter and decoder configuration
- Whether it's a preloaded pcap

**Location:** `{dataDir}/results/{sessionID}/session.json`

### 2. Automatic Session Restoration

When the server starts, it:
1. Scans the results directory for all session folders
2. Loads `session.json` metadata files
3. Reconstructs missing metadata from filesystem if needed
4. Restores all sessions to the SessionManager

**Code:** `SessionManager.RestoreSessionsFromDisk()` in `cmd/capture/webui/session.go`

### 3. Automatic Metadata Saving

Session metadata is automatically saved when:
- A new session is created (after upload or preload)
- Session status is updated (queued → processing → completed/failed)
- Processing time or packet counts are updated

This ensures metadata is always in sync with the actual session state.

## Benefits

### For Local Development
- Sessions persist when you recompile the backend
- Same IP = same sessions remain accessible
- No need to re-upload files after code changes

### For Production
- Service can restart without losing session history
- Users can still access their analysis results
- Preloaded pcaps remain available after restart

### Self-Healing
- If `session.json` is missing or corrupted, the system attempts to reconstruct it from:
  - Directory timestamps
  - Input file locations (uploads or preloaded pcaps)
  - Presence of result files (.ncap, .ncap.gz)
  - Error log files

## Technical Changes

### Modified Files

1. **`cmd/capture/webui/session.go`**
   - Added `RestoreSessionsFromDisk()` method
   - Added `reconstructSession()` for metadata reconstruction
   - Added `loadSessionMetadata()` and `saveSessionMetadata()` helpers
   - Added `SaveSessionMetadata()` public method
   - Modified `UpdateSessionStatus()` to auto-save metadata

2. **`cmd/capture/webui/server.go`**
   - Added session restoration call in `NewServer()` (service mode)
   - Added metadata saving when preloaded pcaps are queued
   - Imports: Added `encoding/json`, `fmt`, `os`, `path/filepath`, `strings`

3. **`cmd/capture/webui/service_handlers.go`**
   - Added metadata saving after user uploads

## Usage

### No Configuration Required
The feature works automatically. Sessions are restored on server startup without any configuration changes.

### Verifying Session Persistence

1. Start the server and upload a file or let it load preloaded pcaps
2. Stop the server
3. Restart the server
4. Check logs for: `[SessionManager] Successfully restored X session(s) from disk`
5. Sessions should be accessible with the same session IDs

### Session Directory Structure

```
{dataDir}/
├── results/
│   ├── {sessionID}/
│   │   ├── session.json          # NEW: Session metadata
│   │   ├── TCP.ncap.gz           # Audit records
│   │   ├── HTTP.ncap.gz
│   │   ├── files/                # Extracted files
│   │   └── analysis_error.log    # Error log (if failed)
├── uploads/
│   └── {sessionID}.pcap          # Uploaded file
└── pcaps/
    └── preloaded.pcapng          # Preloaded pcaps
```

## Error Handling

- If session restoration fails, it's logged as a warning but doesn't stop the server
- Invalid or corrupted metadata files trigger reconstruction
- Missing input files are noted but don't prevent session restoration
- Sessions with no result files are marked as "queued" status

## Logging

Key log messages:
- `[SessionManager] Restoring sessions from disk...`
- `[SessionManager] Restored session X (IP: Y, file: Z, status: W)`
- `[SessionManager] Successfully restored N session(s) from disk`
- `[SessionManager] Warning: Failed to save session metadata for X: Y`

## Future Enhancements

Possible improvements:
- Periodic metadata saves (not just on status changes)
- Session metadata versioning for backward compatibility
- Compression of old session metadata
- Session metadata backup/restore tools

