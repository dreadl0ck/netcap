# Panic Recovery Implementation

## Overview

This document describes the panic recovery mechanism implemented for NETCAP's pcap file processing functionality. The implementation ensures that any panics occurring during pcap file processing are caught, logged to `netcap.log`, and followed by a clean exit with proper file closure and flushing.

## Implementation Details

### Core Panic Recovery Function

A new method `recoverFromPanic()` has been added to the `Collector` struct in `collector/collector.go`. This function:

1. **Catches panics** using Go's `recover()` mechanism
2. **Captures the stack trace** using `runtime/debug.Stack()`
3. **Logs to multiple destinations**:
   - `netcap.log` file (if available)
   - `collector.log` file (if available)
   - Standard error (stderr) for immediate visibility
4. **Flushes log files** to ensure panic details are written to disk
5. **Triggers cleanup** by calling `c.cleanup(true)` to ensure all files are closed and flushed
6. **Exits gracefully** with error code 1

### Protected Functions

The panic recovery has been added to all pcap processing entry points:

1. **`CollectPcap()`** in `collector/pcap.go`
   - Processes standard PCAP files
   
2. **`CollectPcapNG()`** in `collector/pcapNG.go`
   - Processes PCAP-NG files
   
3. **`CollectBPF()`** in `collector/bpf.go`
   - Processes PCAP files with BPF filters
   
4. **`CollectLive()`** in `collector/live.go` (macOS)
   - Handles live packet capture on macOS
   
5. **`CollectLive()`** in `collector/live_linux.go` (Linux)
   - Handles live packet capture on Linux

Each function now starts with:
```go
defer c.recoverFromPanic()
```

## Example Log Output

When a panic occurs during processing, the following information is logged to `netcap.log`:

```
PANIC during pcap processing: <panic message>
Stack trace:
goroutine 1 [running]:
runtime/debug.Stack()
	/usr/local/go/src/runtime/debug/stack.go:24 +0x64
github.com/dreadl0ck/netcap/collector.(*Collector).recoverFromPanic()
	/path/to/collector/collector.go:186 +0x48
...
```

The same information is also written to stderr for immediate visibility:

```
PANIC during pcap processing: <panic message>
Stack trace:
<full stack trace>
Panic details have been written to netcap.log
```

## Cleanup Process

When a panic is caught, the following cleanup steps are performed (via `c.cleanup(true)`):

1. **Stop all workers** - Gracefully halt packet processing workers
2. **Wait for pending operations** - Allow in-flight packet processing to complete
3. **Flush decoders** - Flush all gopacket decoders, custom decoders, stream decoders, and abstract decoders
4. **Close network connections** - Close alert sockets if active
5. **Save databases** - Save fingerprint databases
6. **Sync pcap files** - Flush and close pcap file handles
7. **Close error logs** - Close error log files
8. **Display statistics** - Show final processing statistics
9. **Sync all log files** - Flush all zap loggers and close log file handles

## Testing

A unit test has been added in `collector/panic_recovery_test.go` that verifies:
- The panic recovery mechanism is properly initialized
- The function can be called without side effects when no panic occurs
- The logging infrastructure is properly set up

## Benefits

1. **Improved reliability** - Panics no longer cause abrupt termination with data loss
2. **Better debugging** - Full stack traces are captured and logged for investigation
3. **Data integrity** - All files are properly closed and flushed before exit
4. **Production readiness** - Graceful error handling suitable for production environments
5. **Visibility** - Panic details are logged to multiple destinations for easy troubleshooting

## Files Modified

- `collector/collector.go` - Added `recoverFromPanic()` method
- `collector/pcap.go` - Added panic recovery to `CollectPcap()`
- `collector/pcapNG.go` - Added panic recovery to `CollectPcapNG()`
- `collector/bpf.go` - Added panic recovery to `CollectBPF()`
- `collector/live.go` - Added panic recovery to `CollectLive()` (macOS version)
- `collector/live_linux.go` - Added panic recovery to `CollectLive()` (Linux version)
- `collector/panic_recovery_test.go` - Added unit test for panic recovery mechanism

## Usage

No changes are required to use this feature. The panic recovery is automatically active for all pcap processing operations. Simply check the `netcap.log` file if a panic occurs to see the full details.

