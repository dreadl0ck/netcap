# Debugging Multi-File Directory Switching

If audit records show "0 audit record type(s) available" after switching files, here's how to debug:

## Problem

When you click on a different input file in multi-file mode, the Audit Records page shows 0 records instead of displaying the records for that file.

## Debugging Steps

### 1. Check Backend Logs

After clicking a file, watch the terminal for these log messages:

```bash
# When you click a file:
[WebUI] POST /api/set-directory
[WebUI] Active directory changed to: /tmp/output/file2.pcap (for file: /path/to/file2.pcap)

# When the Audit Records page refreshes:
[WebUI] GET /api/files/audit
[WebUI] Reading audit files from: /tmp/output/file2.pcap (active file: /path/to/file2.pcap)
[WebUI] Found 15 files in directory
[WebUI] Returning 8 audit files
```

**If you see:**
```
[WebUI] Reading audit files from:  (active file: )
[WebUI] Output directory is empty, returning empty list
```

This means `outDir` is empty. The directory wasn't set correctly.

### 2. Check Browser Console

Open browser console (F12) and look for:

```javascript
Directory changed to: /tmp/output/file2.pcap
Directory changed, refreshing audit files...
```

**If you don't see these messages:**
- The frontend isn't receiving the API response
- Check Network tab for `/api/set-directory` request

### 3. Check Network Tab

In browser DevTools → Network tab:

**POST `/api/set-directory`:**
```json
Request: { "inputFile": "/path/to/file2.pcap" }

Response: {
  "success": true,
  "outputDir": "/tmp/output/file2.pcap",
  "activeInputFile": "/path/to/file2.pcap"
}
```

**GET `/api/files/audit` (after switch):**
```json
Response: [
  {
    "name": "TCP.ncap.gz",
    "path": "/tmp/output/file2.pcap/TCP.ncap.gz",
    "type": "TCP",
    "layer": "Transport Layer",
    "recordCount": 1234,
    "size": 524288
  }
]
```

**If response is `[]` (empty array):**
- Check that the output directory exists on disk
- Verify files were actually created during processing
- Make sure the directory path is correct

### 4. Manual Directory Check

```bash
# Check if the directory exists and has files
ls -la /tmp/output/file2.pcap/

# Should show .ncap.gz files:
TCP.ncap.gz
UDP.ncap.gz
DNS.ncap.gz
...
```

### 5. Check File Completion Status

```bash
# In browser console, check the file status:
fetch('/api/files/input').then(r => r.json()).then(console.log)
```

Look for `isCompleted: true` for the file you're trying to view. If `false`, the backend will reject the request.

## Common Issues

### Issue 1: Directory Not Created Yet

**Symptom:** File shows as completed but directory doesn't exist

**Cause:** Processing finished but files weren't written

**Solution:** Check if processing actually completed successfully

### Issue 2: Wrong Directory Path

**Symptom:** Logs show wrong path like `/tmp/output/file2.pcap.pcap`

**Cause:** `getOutputDirForFile` logic might be double-applying the basename

**Fix:** Check `main.go` for correct path construction:
```go
newOutDir := filepath.Join(s.baseOutDir, filepath.Base(req.InputFile))
```

Should produce: `/tmp/output/file.pcap` not `/tmp/output/file.pcap.pcap`

### Issue 3: Race Condition

**Symptom:** Audit page loads before directory is set

**Cause:** Frontend didn't wait for directory change to complete

**Fix:** The event listener should trigger a refresh:
```typescript
window.addEventListener('directory-changed', handleDirectoryChange);
```

### Issue 4: SWR Cache Stale

**Symptom:** Old data shown even after switching

**Cause:** SWR is serving cached data

**Fix:** The `mutate()` call should force a refresh. Try hard refresh: `Ctrl+Shift+R`

## Testing the Fix

1. **Start with multiple files:**
```bash
./bin/net capture \
  -read file1.pcap \
  -read file2.pcap \
  -out /tmp/test \
  -http localhost:8080
```

2. **Wait for at least one file to complete** (look for log message)

3. **Click on the completed file** in Files page

4. **Check terminal immediately:**
```
[WebUI] POST /api/set-directory
[WebUI] Active directory changed to: /tmp/test/file1.pcap
```

5. **Navigate to Audit Records page**

6. **Check terminal:**
```
[WebUI] GET /api/files/audit
[WebUI] Reading audit files from: /tmp/test/file1.pcap (active file: /path/to/file1.pcap)
[WebUI] Found 15 files in directory
[WebUI] Returning 8 audit files
```

7. **Verify UI shows records** with "8 audit record type(s) available"

## If Still Not Working

### Check Initial Active File

The first completed file should be automatically selected. Check logs at startup:

```bash
[WebUI] File marked as completed: /path/to/file1.pcap
```

Then when you load Audit Records for the first time:
```bash
[WebUI] Reading audit files from: /tmp/test/file1.pcap
```

### Force Refresh

Try clicking the same file again - it should reject with:
```
HTTP 400: File processing not yet complete
```

OR if completed:
```
success: true
```

### Check Base Directory

Make sure `baseOutDir` is set correctly:
```go
// In NewServer:
baseOutDir:   outDir,  // Should be "/tmp/test"
```

Then when switching:
```go
newOutDir := filepath.Join(s.baseOutDir, filepath.Base(req.InputFile))
// Should produce: "/tmp/test/file1.pcap"
```

## Success Criteria

✅ Terminal shows correct directory path  
✅ Browser console logs directory change  
✅ Network tab shows non-empty response  
✅ UI displays audit record types  
✅ Layer column shows "Link Layer", "Network Layer", etc.  
✅ Record counts are non-zero  
✅ "View Records" button works  

If all criteria are met, the fix is working correctly!

