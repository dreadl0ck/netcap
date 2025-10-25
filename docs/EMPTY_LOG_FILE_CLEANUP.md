# Empty Log File Cleanup

## Overview

This document describes the automatic cleanup behavior for empty log files in NETCAP, which was implemented to maintain consistency with how empty audit record files are handled.

## Behavior

When NETCAP finishes processing (either from live capture or PCAP file processing), it performs the following cleanup operations:

1. **Flush all loggers** - All zap loggers are synchronized to ensure all buffered log entries are written to disk
2. **Close log file handles** - All log file handles are properly closed after syncing
3. **Check for empty files** - After closing, each log file is checked to see if it's empty (size = 0 bytes)
4. **Remove empty files** - Empty log files are automatically deleted to avoid cluttering the output directory

## Affected Log Files

The following log files are subject to automatic removal if empty:

- `netcap.log` - Main NETCAP execution log
- `collector.log` - Collector-specific debug logs
- `decoder.log` - Decoder-specific debug logs
- `io.log` - I/O operations debug logs
- `resolvers.log` - Resolver (DNS, GeoIP, MAC, etc.) debug logs
- `reassembly.log` - TCP stream reassembly debug logs
- `db.log` - Database operations debug logs
- `errors.log` - Packet decoding errors and stack traces

## Implementation Details

### Code Changes

**`collector/cleanup.go`** (lines 210-238):
- Modified the log file closing loop in `teardown()` to:
  1. Get file info (including size) before closing
  2. Store the filename for post-close removal
  3. Sync and close the file handle
  4. Remove the file if its size is 0 bytes

**`collector/collector.go`** (lines 410-459):
- Updated `closeErrorLogFile()` method to:
  1. Get file info after writing error summary
  2. Store the filename
  3. Sync and close the file handle
  4. Remove the file if its size is 0 bytes

### Rationale

This behavior provides several benefits:

1. **Consistency** - Matches the existing behavior for empty audit record files (`.ncap`, `.ncap.gz`)
2. **Clean output directories** - Reduces clutter from empty log files when no debug logging occurred
3. **Storage efficiency** - Prevents accumulation of empty files over many runs
4. **User experience** - Users only see log files that contain actual information

## Platform-Specific Notes

### Windows

On Windows systems, there may be timing issues that prevent empty log file removal in some cases. This is due to Windows file locking behavior where a file cannot be reopened immediately after closing by the same process. This is the same limitation that affects empty audit record file removal on Windows.

### Linux and macOS

Empty log file removal works reliably on Unix-like systems (Linux, macOS, BSD) as these platforms allow immediate file operations after closing.

## Comparison with Audit Record File Cleanup

The log file cleanup behavior mirrors the audit record file cleanup:

| Aspect | Audit Record Files | Log Files |
|--------|-------------------|-----------|
| **When checked** | After closing file handles | After closing file handles |
| **Empty criteria** | Size = 0 or only contains header | Size = 0 |
| **Action** | Remove file | Remove file |
| **Windows behavior** | May fail due to file locking | May fail due to file locking |
| **Debug output** | Logged to io.log | Logged to stdout |

## Related Documentation

- [docs/logging.md](logging.md) - Log file documentation
- [docs/live-collection.md](live-collection.md) - Live capture documentation including Windows file removal notes
- [io/file_utils.go](../io/file_utils.go) - `removeAuditRecordFileIfEmpty()` function
- [collector/pcap_utils.go](../collector/pcap_utils.go) - PCAP file cleanup implementation

## Testing

To verify this behavior:

1. Run NETCAP with `-debug` flag on a small PCAP file
2. Observe which log files are created
3. Check which log files remain after processing completes
4. Only non-empty log files should remain

Example:
```bash
# Run capture on small PCAP
./net capture -r small.pcap -out /tmp/test -debug

# Check which log files were created and remain
ls -lh /tmp/test/*.log
```

## Future Enhancements

Potential improvements to consider:

1. Add configuration flag to control empty file removal behavior
2. Add debug logging to show which files are being removed
3. Implement retry logic for Windows file removal with configurable delay
4. Consider removing log files that only contain boilerplate headers but no actual log entries

