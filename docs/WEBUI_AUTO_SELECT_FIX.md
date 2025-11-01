# WebUI Auto-Select File Fix

## Problem

When the service is started and files are being processed, users navigating to any page with a capture file selector would see finished capture files in the dropdown, but the file shown was not actually selected until the user made the selection manually. This caused data to not load correctly even though files were visible in the selector.

## Root Cause

The backend's `activeInputFile` state variable is only set when a user manually calls the `setActiveDirectory` API endpoint. When files complete processing, the backend doesn't automatically select one, leaving `activeInputFile` unset. This means:

1. The frontend shows files in the selector dropdown
2. The selector displays the first file as if it were selected (UI fallback)
3. But the backend doesn't know which file to serve data from
4. Result: No data loads until user manually selects a file

## Solution

Added auto-selection logic to all pages with capture file selectors that:

1. **Detects when auto-selection is needed**: Checks if there are completed files available but no active file is set in the backend
2. **Auto-selects the first file**: Calls `api.setActiveDirectory()` with the first completed file's path
3. **Refreshes data**: Triggers data refresh after selection so content loads immediately
4. **Runs once**: Uses a state flag `autoSelectAttempted` to ensure this only happens once per page load

## Files Changed

### Frontend (TypeScript/React)

1. **cmd/capture/webui/frontend/src/pages/explore.tsx**
   - Added `autoSelectAttempted` state
   - Added `useEffect` hook for auto-selection logic
   - Auto-refreshes audit files after selection

2. **cmd/capture/webui/frontend/src/pages/audit.tsx**
   - Added `autoSelectAttempted` state
   - Added `useEffect` hook for auto-selection logic
   - Auto-refreshes audit files after selection

3. **cmd/capture/webui/frontend/src/pages/logs.tsx**
   - Added `autoSelectAttempted` state
   - Added `useEffect` hook for auto-selection logic
   - Auto-refreshes log files after selection

4. **cmd/capture/webui/frontend/src/pages/visualize.tsx**
   - Added `autoSelectAttempted` state
   - Added `useEffect` hook for auto-selection logic
   - Auto-refreshes hierarchy data after selection

## Implementation Details

The auto-selection logic follows this pattern on each affected page:

```typescript
const [autoSelectAttempted, setAutoSelectAttempted] = useState(false);

useEffect(() => {
  const autoSelectFirstFile = async () => {
    // Only attempt once
    if (autoSelectAttempted) return;
    
    // Wait for data to be loaded
    if (!inputFiles || !status) return;
    
    const completed = inputFiles.filter((f: any) => f.isCompleted);
    if (completed.length === 0) return;
    
    // Check if we need to auto-select
    const hasActiveFile = status.activeInputFile && completed.some((f: any) => 
      f.path === status.activeInputFile || 
      f.name === status.activeInputFile || 
      f.path.endsWith('/' + status.activeInputFile)
    );
    
    if (!hasActiveFile) {
      console.log('[PageName] Auto-selecting first completed file:', completed[0].path);
      setAutoSelectAttempted(true);
      try {
        await api.setActiveDirectory(completed[0].path);
        await mutateStatus();
        // Refresh page-specific data...
      } catch (err) {
        console.error('[PageName] Failed to auto-select file:', err);
      }
    }
  };
  
  autoSelectFirstFile();
}, [inputFiles, status, autoSelectAttempted, mutateStatus, /* other deps */]);
```

## Testing

To verify the fix works:

1. Start the netcap service with multiple PCAP files to process
2. While files are being processed, navigate to any page with a file selector (Explore, Audit, Logs, or Visualize)
3. Verify that:
   - The first completed file is automatically selected in the dropdown
   - Data loads correctly for that file without manual selection
   - The "Active" badge appears on the selected file
   - Page-specific data (charts, audit records, logs, etc.) displays immediately

## Benefits

- **Improved UX**: Users can immediately view data without manual file selection
- **Consistent behavior**: All pages with file selectors behave uniformly
- **No breaking changes**: Manual file selection still works as before
- **Multi-file support**: Properly handles scenarios with multiple input files
- **Error resilient**: Gracefully handles errors during auto-selection

## Future Considerations

- Could be enhanced to remember user's last selected file (local storage)
- Could auto-select newest file instead of first alphabetically
- Could add user preference for auto-selection behavior

