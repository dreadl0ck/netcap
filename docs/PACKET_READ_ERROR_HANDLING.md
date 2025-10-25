# Packet Read Error Handling

## Overview

When processing multiple PCAP files, packet reading errors (such as "capture length exceeds original packet length") are now handled gracefully. Instead of terminating the entire batch processing with exit status 1, these errors are logged in the summary table and processing continues with the next file.

## Changes Made

### collector/pcap.go

**Problem**: The `countPackets` function used `log.Fatal()` when encountering packet reading errors during the packet counting phase. This caused immediate program termination, even when processing multiple files in batch mode.

**Solution**: Changed the error handling to return the error instead of calling `log.Fatal()`. This allows the error to propagate up to the batch processing logic where it's properly caught and logged.

**Modified lines 225-239**:
```go
for {
    // loop over packets and discard all data
    _, _, err = r.ZeroCopyReadPacketData()
    if err != nil {
        if errors.Is(err, io.EOF) {
            break
        }
        return count, errors.Wrap(err, errReadingPacketData)  // Changed from log.Fatal
    }

    // increment counter
    count++
}
```

Also removed unused `log` import from the file.

## Error Flow

1. **Packet Counting Phase** (`countPackets`):
   - Errors during counting are now returned as regular errors
   - These propagate to `CollectPcap()` which returns them to the caller

2. **Batch Processing** (`cmd/capture/main.go` lines 908-916):
   - Errors from `CollectPcap()` are caught
   - Error is added to `fileErrors` slice
   - Processing continues with next file

3. **Summary Table**:
   - All errors are displayed in the summary table at the end
   - Shows which files failed and why
   - Displays success/failure statistics

## Example Error Handling

When processing multiple files, an error like:
```
error reading packet data: capture length exceeds original packet length: 92 > 76
```

Will now:
1. Be logged to stdout with details
2. Be added to the error tracking system
3. Appear in the final summary table
4. Allow processing to continue with the next file

Instead of:
1. Calling `log.Fatal()`
2. Exiting with status 1
3. Stopping all remaining files from being processed

## Related Files

- `collector/pcap.go` - PCAP file reading and packet counting
- `collector/pcapNG.go` - PCAPNG file reading (already had proper error handling)
- `cmd/capture/main.go` - Batch processing orchestration and error tracking

## Testing

To test the error handling:

```bash
# Create a batch of files including some with corrupt packets
net capture -r "*.pcap"
```

Files with packet reading errors will be logged in the summary table and marked with ERROR status, while valid files will continue to be processed.

