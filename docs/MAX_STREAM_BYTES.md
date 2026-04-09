# Maximum Stream Bytes Feature

> **📚 For comprehensive documentation covering all stream reassembly limits, see [STREAM_REASSEMBLY_LIMITS.md](STREAM_REASSEMBLY_LIMITS.md)**

## Overview

The `MaxStreamBytes` feature allows you to configure a size limit for the maximum number of bytes to reassemble from a single TCP stream direction before the stream is marked as closed for performance reasons. This is useful when dealing with large data transfers that could consume excessive memory or processing time.

This is one of **three stream reassembly limits** available in netcap:
1. **MaxStreamBytes** - Total stream size limit (this document)
2. **MaxBufferedPagesPerConnection** - Per-connection reorder buffer limit
3. **MaxBufferedPagesTotal** - Global reorder buffer limit

See [STREAM_REASSEMBLY_LIMITS.md](STREAM_REASSEMBLY_LIMITS.md) for detailed comparison and usage examples.

## Configuration

### Default Behavior

By default, `MaxStreamBytes` is set to **10MB (10,485,760 bytes)** per stream direction. This prevents excessive memory usage from large file transfers while still allowing most protocol conversations to be fully captured.

To disable the limit and allow unlimited reassembly, set the value to `0`.

### Setting the Limit

You can configure the limit in several ways:

#### 1. Command-line Flag (Recommended)

When using the `net capture` command:

```bash
# Use default 10MB limit
net capture -read input.pcap

# Set custom limit (e.g., 50MB)
net capture -read input.pcap -max-stream-bytes 52428800

# Disable limit (unlimited reassembly)
net capture -read input.pcap -max-stream-bytes 0
```

#### 2. Configuration File

Add to your `net.capture.conf`:

```conf
# maximum number of bytes to reassemble per stream direction (0 = unlimited)
max-stream-bytes 10485760
```

#### 3. Programmatically

When using netcap as a library:

```go
import (
    "github.com/dreadl0ck/netcap/collector"
    "github.com/dreadl0ck/netcap/decoder/config"
)

// Use default configuration (10MB limit)
cfg := collector.Config{
    DecoderConfig: config.DefaultConfig,
    // ... other collector options
}

// Or customize the limit
cfg := collector.Config{
    DecoderConfig: &config.Config{
        MaxStreamBytes: 52428800, // 50MB per stream direction
        // ... other config options
    },
    // ... other collector options
}

// Disable limit (unlimited)
cfg := collector.Config{
    DecoderConfig: &config.Config{
        MaxStreamBytes: 0, // unlimited
        // ... other config options
    },
    // ... other collector options
}

// Create and initialize the collector
c := collector.New(cfg)
```

## How It Works

### Stream Direction Tracking

- The limit is applied **per stream direction** (client-to-server and server-to-client separately)
- Each direction tracks its own byte count independently
- When a direction reaches the limit, it is marked as closed
- Further packets for that direction are ignored by the reassembly engine

### Implementation Details

1. **Byte Tracking**: The `halfconnection` struct tracks `totalBytes` - the cumulative count of bytes reassembled for that direction

2. **Limit Check**: After queuing new bytes, the assembler checks if `totalBytes >= MaxStreamBytes`

3. **Stream Closure**: When the limit is reached, the half-connection is marked as `closed`

4. **Performance**: Closed half-connections reject further packets in the `Accept()` callback, minimizing overhead

## Use Cases

### 1. Memory Conservation

Large file transfers or continuous data streams can consume significant memory:

```bash
# Limit each stream direction to 50MB
net capture -iface eth0 -max-stream-bytes 52428800
```

### 2. Performance Optimization

When you only need to inspect the beginning of connections:

```bash
# Capture only the first 1MB of each stream direction
net capture -read traffic.pcap -max-stream-bytes 1048576
```

### 3. Protocol Analysis

For protocols where initial handshake/headers are sufficient:

```bash
# Limit to 64KB to capture headers and initial payload
net capture -read traffic.pcap -max-stream-bytes 65536
```

## Example Values

Common values and their use cases:

| Value | Size | Use Case |
|-------|------|----------|
| 0 | Unlimited | Full capture (use with caution) |
| 65536 | 64 KB | Headers and small payloads |
| 1048576 | 1 MB | Initial protocol negotiation |
| 10485760 | 10 MB | Moderate file transfers (default) |
| 52428800 | 50 MB | Large file transfers |
| 104857600 | 100 MB | Very large transfers with limit |

## Monitoring

When debug mode is enabled (`-debug` flag), the assembler will log when the byte limit is reached:

```
hit max stream bytes: 10485760 >= 10485760, closing half connection
```

## Technical Details

### Modified Components

1. **decoder/config/config.go**: Added `MaxStreamBytes` field to Config struct
2. **reassembly/assembler.go**: 
   - Added `MaxStreamBytes` field to assemblerOptions
   - Implemented byte limit check in `handleBytes()`
   - Track bytes in `checkOverlap()`
3. **reassembly/halfconnection.go**: Added `totalBytes` tracking field
4. **collector/worker.go**: Wire up MaxStreamBytes from config to assembler
5. **cmd/capture/**: Added command-line flag support

### Backward Compatibility

**Important**: The default has changed from unlimited to 10MB per stream direction:
- **Old default**: 0 (unlimited) - could cause memory issues with large transfers
- **New default**: 10485760 (10MB) - prevents excessive memory usage while supporting most use cases
- To restore unlimited behavior, explicitly set `-max-stream-bytes 0`
- Existing configurations without this setting will now use the 10MB limit
- Tests verify both limited and unlimited modes work correctly

## Testing

The feature includes comprehensive unit tests:

```bash
cd reassembly
go test -v -run TestMaxStreamBytes
```

Tests verify:
- Configuration can be set and retrieved
- Limited mode applies the byte limit correctly
- Unlimited mode (default) continues to work as before
- The assembler doesn't panic when limits are reached

## Performance Impact

- **Minimal Overhead**: Single integer comparison per packet
- **Memory Savings**: Can reduce memory usage significantly for large transfers
- **CPU Reduction**: Avoids processing beyond the configured limit
- **No Impact When Disabled**: Zero overhead when set to 0 (unlimited)

## Future Enhancements

Potential future improvements:
- Per-protocol byte limits
- Separate limits for client vs server directions
- Dynamic limit adjustment based on available memory
- Statistics on streams that hit the limit

