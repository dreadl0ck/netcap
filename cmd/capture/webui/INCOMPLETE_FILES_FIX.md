# Fix for Incomplete Audit Record Files

This document describes the fix for the issue where audit records stop loading after a while due to files being read while still being written.

## Problem Description

**Symptom**: After viewing audit records for a while, clicking "View Records" on some files would show a loading spinner indefinitely, with no records displayed.

**Root Cause**: Files were being listed in the UI while still being actively written during processing. When users tried to view these incomplete files, the reader would encounter EOF errors because:
1. The file header was incomplete or not yet written
2. The file was being written by the capture process
3. The gzip stream was incomplete

**Error in logs**:
```
2025/10/26 19:36:20 [WebUI] Opening audit file: DEF CON 23 ICS Village/IPProfile.ncap.gz
2025/10/26 19:36:20 [WebUI] Failed to open audit file: EOF
```

## Solution Implemented

### 1. Backend: Better Error Handling and Detection

#### File Listing (handlers.go)
When listing audit files, we now detect files that can't be counted:

```go
count, err := netio.Count(fullPath)
if err == nil {
    auditFile.RecordCount = count
} else {
    // If we can't count records, the file might be incomplete or being written
    // Set recordCount to 0 so it gets filtered out by the frontend
    log.Printf("[WebUI] Failed to count records for %s: %v (file may be incomplete)", fullPath, err)
    auditFile.RecordCount = 0
}
```

**Effect**: Files that are incomplete or being written will have `recordCount: 0` and be automatically filtered by the frontend's empty file filter.

#### Stream Endpoint (handlers.go)
Added specific EOF detection with user-friendly error messages:

```go
reader, err := NewAuditRecordReader(filePath)
if err != nil {
    log.Printf("[WebUI] Failed to open audit file: %v", err)
    if err == io.EOF {
        http.Error(w, "Audit record file is incomplete or being written. Please try again later.", http.StatusServiceUnavailable)
    } else {
        http.Error(w, fmt.Sprintf("Failed to open audit record file: %v", err), http.StatusInternalServerError)
    }
    return
}

// Read header
_, err = reader.ReadHeader()
if err != nil {
    log.Printf("[WebUI] Failed to read header: %v", err)
    if err == io.EOF {
        http.Error(w, "Audit record file is incomplete or being written. Please try again later.", http.StatusServiceUnavailable)
    } else {
        http.Error(w, fmt.Sprintf("Failed to read header: %v", err), http.StatusInternalServerError)
    }
    return
}
```

**Effect**: Users get clear error messages instead of hanging indefinitely.

#### Metadata Endpoint (handlers.go)
Same EOF handling added to the metadata endpoint:

```go
reader, err := NewAuditRecordReader(filePath)
if err != nil {
    if err == io.EOF {
        http.Error(w, "Audit record file is incomplete or being written. Please try again later.", http.StatusServiceUnavailable)
    } else {
        http.Error(w, fmt.Sprintf("Failed to open audit record file: %v", err), http.StatusInternalServerError)
    }
    return
}
```

### 2. Frontend: Error Display and Retry (audit.tsx)

#### Added Error State
```typescript
const [streamError, setStreamError] = useState<string | null>(null);
```

#### Clear Error on New Request
```typescript
const handleViewRecords = (type: string) => {
    // ... existing code ...
    setStreamError(null); // Clear previous errors
    // ... rest of code ...
}
```

#### Capture Errors from Stream
```typescript
(error) => {
    console.error('Stream error:', error);
    setStreamError(error);
    setLoading(false);
}
```

#### Display Error UI with Retry Button
```typescript
{streamError ? (
    <Box p={3}>
        <Typography color="error" variant="h6" gutterBottom>
            Unable to load records
        </Typography>
        <Typography color="text.secondary" paragraph>
            {streamError}
        </Typography>
        {streamError.includes('incomplete') && (
            <Box mt={2}>
                <Typography variant="body2" color="text.secondary" paragraph>
                    This file is currently being written. Please wait for processing to complete and try again.
                </Typography>
                <Button 
                    variant="outlined" 
                    onClick={() => handleViewRecords(selectedType!)}
                    sx={{ mt: 1 }}
                >
                    Retry
                </Button>
            </Box>
        )}
    </Box>
) : // ... rest of dialog content ...
```

## How It Works

### Scenario 1: File Being Written (Most Common)

1. **File appears in list** with `recordCount: 0` (counting failed)
2. **Frontend filters it out** (empty file filter)
3. **File not shown** to user
4. **After completion**, `recordCount > 0`, file appears in list

### Scenario 2: User Clicks Before Filter Applies

1. **User clicks** "View Records" on incomplete file
2. **Backend detects EOF** when reading header
3. **Returns HTTP 503** with message: "Audit record file is incomplete or being written. Please try again later."
4. **Frontend shows error** with explanation and Retry button
5. **User can retry** after processing completes

### Scenario 3: File Becomes Complete

1. **Processing completes** for a file
2. **WebUI marks file as completed**: `MarkFileCompleted(inputFile)`
3. **Next refresh** shows correct `recordCount`
4. **File appears** in audit records list
5. **User can view** records successfully

## User Experience

### Before Fix
- ❌ Loading spinner forever
- ❌ No feedback about what's wrong
- ❌ Must reload page or switch files
- ❌ Confusing and frustrating

### After Fix
- ✅ Files being written are hidden automatically
- ✅ Clear error message if EOF occurs
- ✅ Helpful explanation about file being written
- ✅ One-click retry button
- ✅ Professional user experience

## Example Error Messages

### Backend Log
```
[WebUI] Failed to count records for DEF CON 23 ICS Village/IPProfile.ncap.gz: EOF (file may be incomplete)
[WebUI] Failed to open audit file: EOF
```

### User-Facing Error
```
Unable to load records

Audit record file is incomplete or being written. Please try again later.

This file is currently being written. Please wait for processing to complete and try again.

[Retry Button]
```

## Prevention Strategy

### Multiple Layers of Protection

1. **Layer 1**: Count records when listing files
   - Incomplete files get `recordCount: 0`
   - Filtered out by frontend

2. **Layer 2**: Check file when opening reader
   - EOF detected early
   - User-friendly error returned

3. **Layer 3**: Check header when streaming
   - Final verification before streaming
   - Prevents partial data corruption

4. **Layer 4**: Frontend error handling
   - Displays errors gracefully
   - Provides retry mechanism
   - Educates user about situation

## Testing

### Test Case 1: File Being Written
```bash
# Start processing
./bin/net capture -read huge.pcap -out /tmp/test -http :8080

# In browser: Try to view records while processing
# Expected: File not shown (0 records) OR error with retry
```

### Test Case 2: Complete File
```bash
# Wait for processing to complete
# Expected: File appears with correct record count
# Expected: Can view records successfully
```

### Test Case 3: Corrupted File
```bash
# Create empty file
touch /tmp/test/Broken.ncap.gz

# In browser: Try to view
# Expected: Clear error message (not EOF, but handled)
```

## Files Modified

1. **Backend**:
   - `/cmd/capture/webui/handlers.go` - Error handling in 3 places
   
2. **Frontend**:
   - `/cmd/capture/webui/frontend/src/pages/audit.tsx` - Error display and retry

## Status Codes

- **200 OK**: File read successfully
- **404 Not Found**: File doesn't exist
- **500 Internal Server Error**: Unexpected error
- **503 Service Unavailable**: File incomplete/being written (temporary, retry later)

## Future Improvements

Potential enhancements:
1. **Auto-refresh**: Automatically retry failed requests after delay
2. **File locking detection**: Check if file is open for writing
3. **Modification time check**: Skip files modified in last N seconds
4. **Progress indicator**: Show which files are being written
5. **Websocket notifications**: Real-time updates when files complete

## Summary

The fix provides **robust handling of incomplete files** through:
- ✅ Automatic filtering of files being written
- ✅ Clear error messages for edge cases
- ✅ User-friendly retry mechanism
- ✅ Multiple layers of protection
- ✅ Professional user experience

Users now get clear feedback and can easily retry once processing completes, eliminating the frustrating "infinite loading" issue.

