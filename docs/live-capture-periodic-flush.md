# Live Capture Periodic Flushing

This document describes the periodic flushing feature for live network capture operations in netcap.

## Overview

When running netcap in live capture mode, audit records are buffered in memory before being written to disk. By default, this data is only flushed when the capture is stopped (via SIGINT/SIGTERM or context cancellation). This means that during long-running live captures, the audit record files remain empty or incomplete until shutdown.

The **periodic flushing** feature addresses this by writing audit records to disk at configurable intervals during live capture, making data available for analysis while capture is ongoing.

## Key Concepts

### Immediate vs Accumulating Decoders

Netcap has two types of decoders with different flushing behaviors:

1. **Immediate Decoders**: Write records as soon as packets are processed
   - GoPacket decoders (TCP, UDP, DNS, etc.)
   - Stream decoders (HTTP, TLS, SMTP, etc.)
   - These only need their I/O buffers flushed

2. **Accumulating Decoders**: Build up state over time and write at the end
   - `DeviceProfile` - Tracks devices by MAC address
   - `IPProfile` - Tracks hosts by IP address
   - `Connection` - Tracks bidirectional network connections
   - These write the **current state** during periodic flushes while keeping the state in memory for continued tracking

### State Preservation

When accumulating decoders flush, they:
- Write the current state of all tracked records to disk
- **Do NOT clear** the in-memory state
- Continue tracking and updating records as new packets arrive

This means the same record (e.g., a DeviceProfile for a specific MAC) may be written multiple times with updated values during a long capture session.

## Configuration

### Collector Configuration

Enable periodic flushing by setting the `LiveFlushInterval` in the collector configuration:

```go
import (
    "time"
    "github.com/dreadl0ck/netcap/collector"
)

cfg := &collector.Config{
    // Flush audit records every 30 seconds during live capture
    LiveFlushInterval: 30 * time.Second,
    
    // ... other configuration options
}
```

### Recommended Intervals

| Use Case | Recommended Interval |
|----------|---------------------|
| Real-time monitoring | 10-15 seconds |
| General analysis | 30-60 seconds |
| Long-term capture | 2-5 minutes |
| Minimal overhead | 0 (disabled) |

Setting `LiveFlushInterval` to 0 (the default) disables periodic flushing.

## Usage Examples

### Basic Live Capture with Periodic Flush

```go
package main

import (
    "context"
    "time"
    
    "github.com/dreadl0ck/netcap/collector"
    "github.com/dreadl0ck/netcap/decoder/config"
)

func main() {
    // Create collector configuration
    cfg := &collector.Config{
        LiveFlushInterval: 30 * time.Second,
        DecoderConfig:     config.DefaultConfig,
        // ... other options
    }
    
    // Create collector
    c := collector.New(cfg)
    
    // Start live capture with periodic flushing
    ctx := context.Background()
    err := c.CollectLive("eth0", "", ctx)
    if err != nil {
        panic(err)
    }
}
```

### Command Line Usage

When using the `net capture` command:

```bash
# Capture on interface eth0 with 30-second flush interval
net capture -iface eth0 -live-flush-interval 30s
```

## Architecture

### Component Interaction

```
┌─────────────────────────────────────────────────────────────────┐
│                         Collector                                │
│                                                                 │
│  ┌──────────────┐    ┌─────────────────────────────────────┐   │
│  │   Periodic   │    │           Decoders                   │   │
│  │   Flush      │───▶│                                      │   │
│  │   Ticker     │    │  ┌─────────────┐  ┌─────────────┐   │   │
│  └──────────────┘    │  │  GoPacket   │  │  Packet     │   │   │
│                      │  │  Decoders   │  │  Decoders   │   │   │
│                      │  │  (flush     │  │  (flush     │   │   │
│                      │  │  buffers)   │  │  state)     │   │   │
│                      │  └──────┬──────┘  └──────┬──────┘   │   │
│                      │         │                 │          │   │
│                      │  ┌─────────────┐  ┌─────────────┐   │   │
│                      │  │  Stream     │  │  Abstract   │   │   │
│                      │  │  Decoders   │  │  Decoders   │   │   │
│                      │  │  (flush     │  │  (flush     │   │   │
│                      │  │  buffers)   │  │  buffers)   │   │   │
│                      │  └──────┬──────┘  └──────┬──────┘   │   │
│                      └─────────┼────────────────┼──────────┘   │
│                                │                │               │
│                                ▼                ▼               │
│                      ┌─────────────────────────────────────┐   │
│                      │         AuditRecordWriters          │   │
│                      │  ┌──────────────────────────────┐   │   │
│                      │  │  Flush() - write buffers     │   │   │
│                      │  │  without closing file        │   │   │
│                      │  └──────────────────────────────┘   │   │
│                      └─────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Flush Process

1. **Ticker fires** at configured interval
2. **Check shutdown state** - skip if collector is shutting down
3. **Flush GoPacket decoders** - call `FlushCurrentState()` on each
4. **Flush Packet decoders** - accumulating decoders write current state
5. **Flush Stream decoders** - call `FlushCurrentState()` on each
6. **Flush Abstract decoders** - call `FlushCurrentState()` on each
7. **Log completion** - record duration and number of records flushed

## Writer Interface

All audit record writers implement the `Flush()` method:

```go
type AuditRecordWriter interface {
    Write(msg proto.Message) error
    WriteHeader(t types.Type) error
    Close(numRecords int64) (name string, size int64)
    Flush() error  // Flush buffers without closing
}
```

### Writer-Specific Behavior

| Writer | Flush Behavior |
|--------|----------------|
| `protoWriter` | Flushes buffer, syncs file to disk |
| `jsonWriter` | Flushes buffer, syncs file to disk |
| `csvWriter` | Flushes buffer, syncs file to disk |
| `elasticWriter` | Sends queued records to Elasticsearch |
| `chanWriter` | No-op (data sent immediately) |
| `nullWriter` | No-op |
| `unixSocketWriter` | Flushes buffer |

## Decoder Interface

All decoders implement `FlushCurrentState()`:

```go
type DecoderAPI interface {
    // ... other methods
    
    // FlushCurrentState writes current state without clearing memory.
    // Returns the number of records flushed.
    FlushCurrentState() int64
}
```

### Decoder-Specific Behavior

| Decoder | FlushCurrentState Behavior |
|---------|---------------------------|
| GoPacket decoders | Flush writer buffer only |
| `DeviceProfile` | Write all profiles, keep in memory |
| `IPProfile` | Write all profiles, keep in memory |
| `Connection` | Write all connections, keep in memory |
| Stream decoders | Flush writer buffer only |
| Abstract decoders | Flush writer buffer only |

## Performance Considerations

### Overhead

- Each flush triggers I/O operations (buffer flush + fsync)
- Accumulating decoders iterate over all tracked records
- More frequent flushes = more overhead, but fresher data

### Memory

- State is preserved in memory between flushes
- No additional memory overhead from the flushing mechanism
- Same records are written multiple times (file grows faster)

### Recommendations

1. **Balance freshness vs overhead**: Start with 30-60 second intervals
2. **Monitor disk I/O**: Frequent flushes increase disk activity
3. **Consider compression**: Compressed output reduces flush overhead
4. **Use for live analysis**: Most useful when actively monitoring output

## File Format Considerations

When periodic flushing is enabled, accumulating decoder output files will contain multiple versions of the same record:

```
# DeviceProfile.ncap.gz might contain:
DeviceProfile { MAC: "aa:bb:cc:dd:ee:ff", NumPackets: 100, ... }  # Flush 1
DeviceProfile { MAC: "aa:bb:cc:dd:ee:ff", NumPackets: 250, ... }  # Flush 2
DeviceProfile { MAC: "aa:bb:cc:dd:ee:ff", NumPackets: 500, ... }  # Final
```

When reading these files, you may want to:
- Use only the last occurrence of each record (most recent state)
- Track changes over time using all occurrences
- The final flush at shutdown contains the definitive final state

## Troubleshooting

### Data Not Appearing

1. Check that `LiveFlushInterval` is set to a non-zero value
2. Verify the output directory has write permissions
3. Check logs for flush errors

### High CPU/Disk Usage

1. Increase the flush interval
2. Enable compression if not already enabled
3. Reduce the number of enabled decoders

### Memory Growth

Periodic flushing does not affect memory usage - state is preserved between flushes. If memory is growing unbounded, check:
- `MaxStreamBytes` limit for stream reassembly
- `MaxBufferedPagesPerConnection` for TCP buffering

## Related Documentation

- [Collector Configuration](collector-configuration.md)
- [Decoder Configuration](decoder-configuration.md)
- [Live Capture Guide](live-capture.md)

