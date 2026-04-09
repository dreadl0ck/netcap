# Decode Options

## Overview

NETCAP uses gopacket for packet decoding, which provides several decoding strategies through the `DecodeOptions` configuration. The decode options control how packets are decoded from raw bytes and can significantly impact performance, memory usage, and concurrency safety.

## Available Options

The `-opts` flag allows you to select different decoding strategies. The available options are:

### 1. `default` (Default)

**Usage:**
```bash
net capture -iface eth0 -opts default
```

**Behavior:**
- Eagerly decodes all layers immediately
- Copies input buffer to packet-owned storage
- **Concurrency-safe**: Multiple goroutines can process the same packet
- **Input buffer safe**: Original buffer can be modified without affecting the packet

**Gopacket Configuration:**
```go
gopacket.DecodeOptions{
    Lazy:   false,
    NoCopy: false,
    Pool:   false,
}
```

**When to Use:**
- Default choice for most use cases
- When using concurrent packet processing
- When buffer safety is required
- When performance is not the primary concern

**Performance Characteristics:**
- **Speed**: Slowest (due to eager decoding and buffer copy)
- **Memory**: Moderate (each packet owns its buffer)
- **Safety**: Highest (fully concurrency-safe)

---

### 2. `lazy`

**Usage:**
```bash
net capture -iface eth0 -opts lazy
```

**Behavior:**
- Decodes layers on-demand (only when accessed)
- Copies input buffer to packet-owned storage
- **NOT concurrency-safe**: Packet state mutates on each layer access
- **Input buffer safe**: Original buffer can be modified

**Gopacket Configuration:**
```go
gopacket.DecodeOptions{
    Lazy:   true,
    NoCopy: false,
    Pool:   false,
}
```

**When to Use:**
- Single-threaded packet processing
- When you only need to access a few layers per packet
- When minimizing decoding overhead is important

**When NOT to Use:**
- Concurrent packet processing (multiple goroutines accessing the same packet)
- When you need to access all layers anyway

**Performance Characteristics:**
- **Speed**: Fast (defers work until needed)
- **Memory**: Moderate (each packet owns its buffer)
- **Safety**: Low (not concurrency-safe, mutates on access)

⚠️ **Warning**: Using `lazy` with concurrent workers may cause race conditions!

---

### 3. `nocopy`

**Usage:**
```bash
net capture -iface eth0 -opts nocopy
```

**Behavior:**
- Eagerly decodes all layers immediately
- Does NOT copy input buffer (uses original buffer directly)
- **Concurrency-safe**: Multiple goroutines can process the same packet
- **Input buffer unsafe**: Original buffer must NOT be modified

**Gopacket Configuration:**
```go
gopacket.DecodeOptions{
    Lazy:   false,
    NoCopy: true,
    Pool:   false,
}
```

**When to Use:**
- When you can guarantee the input buffer won't be modified
- Live capture with dedicated buffer per packet
- Reading from PCAP files in a single-threaded manner

**When NOT to Use:**
- Reusing buffers for multiple packets
- Async I/O where buffers may be reused
- Packet buffering/queuing scenarios

**Performance Characteristics:**
- **Speed**: Fast (no buffer copy overhead)
- **Memory**: Low (no duplicate buffer allocation)
- **Safety**: Moderate (requires careful buffer management)

⚠️ **Warning**: If the underlying buffer is modified, the packet becomes invalid!

---

### 4. `datagrams`

**Usage:**
```bash
net capture -iface eth0 -opts datagrams
```

**Behavior:**
- Eagerly decodes all layers including application layers after TCP/UDP
- Copies input buffer to packet-owned storage
- Enables routing of application-level layers in TCP decoder
- **Concurrency-safe**: Multiple goroutines can process the same packet

**Gopacket Configuration:**
```go
gopacket.DecodeOptions{
    Lazy:                    false,
    NoCopy:                  false,
    Pool:                    false,
    DecodeStreamsAsDatagrams: true,
}
```

**When to Use:**
- When you need application-layer decoding in single packets
- Analyzing stateless protocols (UDP-based applications)
- When NOT using stream reassembly
- Quick packet inspection without connection tracking

**When NOT to Use:**
- With TCP stream reassembly enabled (reassembly package handles this)
- When using the `ReassembleConnections` option

**Performance Characteristics:**
- **Speed**: Slower (decodes more layers)
- **Memory**: Moderate (each packet owns its buffer)
- **Safety**: High (fully concurrency-safe)

**Note**: NETCAP's default configuration uses `default` for safe, eager decoding with full stream processing support.

---

### 5. `pool` (New)

**Usage:**
```bash
net capture -iface eth0 -opts pool
```

**Behavior:**
- Eagerly decodes all layers immediately
- Uses memory pooling for packet buffers (up to MTU size: 1500 bytes)
- Copies input buffer from a reusable memory pool
- **Concurrency-safe**: Multiple goroutines can process the same packet
- **Requires disposal**: Must call `packet.Dispose()` after processing

**Gopacket Configuration:**
```go
gopacket.DecodeOptions{
    Lazy:   false,
    NoCopy: false,
    Pool:   true,
}
```

**When to Use:**
- High-throughput packet capture
- Long-running capture sessions
- When minimizing GC pressure is important
- Processing millions of packets

**When NOT to Use:**
- Short capture sessions (pooling overhead not worth it)
- When packets are small and infrequent
- When you can't guarantee proper disposal

**Performance Characteristics:**
- **Speed**: Fast (reduced allocation overhead)
- **Memory**: Low (reuses buffers, reduces GC pressure)
- **Safety**: High (concurrency-safe with proper disposal)

**Implementation Details:**

When using pool mode, gopacket returns a `PooledPacket` interface:

```go
type PooledPacket interface {
    Packet
    Dispose()
}
```

NETCAP automatically handles disposal in the worker pipeline:

```go
// After packet processing completes
if pooledPkt, ok := pkt.(gopacket.PooledPacket); ok {
    pooledPkt.Dispose()
}
```

**Memory Pool Limits:**
- Pool is only used for packets ≤ 1500 bytes (typical MTU)
- Larger packets fall back to regular allocation
- Pool size is managed by gopacket internally

⚠️ **Warning**: Never access a pooled packet after `Dispose()` is called!

---

## Performance Comparison

| Option      | Speed        | Memory Usage | GC Pressure | Concurrency-Safe | Buffer Safety Required |
|-------------|--------------|--------------|-------------|------------------|------------------------|
| `default`   | Slowest      | Moderate     | Moderate    | ✅ Yes           | No                     |
| `lazy`      | Fast         | Moderate     | Moderate    | ❌ No            | No                     |
| `nocopy`    | Fast         | Low          | Low         | ✅ Yes           | ✅ Yes                 |
| `datagrams` | Slow         | Moderate     | Moderate    | ✅ Yes           | No                     |
| `pool`      | Fast         | Low          | Very Low    | ✅ Yes           | No                     |

## Configuration Examples

### High-Throughput Live Capture
```bash
# Use pool mode for best performance with high packet rates
net capture -iface eth0 -opts pool -workers 16 -pbuf 1000
```

### Memory-Constrained Environment
```bash
# Use nocopy to minimize memory allocations
net capture -iface eth0 -opts nocopy -workers 4
```

### PCAP File Analysis (Single-Threaded)
```bash
# Use lazy for fast single-threaded processing
net capture -read traffic.pcap -opts lazy -workers 1
```

### Stream Analysis Without Reassembly
```bash
# Use datagrams to decode application layers in individual packets
net capture -iface eth0 -opts datagrams
```

### Safe Default Configuration
```bash
# Use default for maximum safety and compatibility
net capture -iface eth0 -opts default
```

## Advanced Considerations

### Combining with Other Flags

**Worker Configuration:**
```bash
# More workers benefit from pool mode (reduces GC contention)
net capture -iface eth0 -opts pool -workers 32
```

**Buffer Configuration:**
```bash
# Larger packet buffer works well with pool mode
net capture -iface eth0 -opts pool -pbuf 5000
```

**Compression:**
```bash
# Pool mode helps when using compression (reduces allocation overhead)
net capture -iface eth0 -opts pool -comp true
```

### Memory Management

**Default Mode:**
- Each packet allocates a new buffer
- GC collects buffers when packets are no longer referenced
- Predictable memory usage

**Pool Mode:**
- Buffers are recycled from a pool
- Much lower GC pressure
- Better for sustained high-throughput scenarios
- NETCAP automatically calls `Dispose()` when packet processing completes

**NoCopy Mode:**
- No duplicate buffers allocated
- Lowest memory usage but requires buffer discipline
- Best for single-threaded or carefully managed scenarios

### Troubleshooting

**High Memory Usage:**
- Try `nocopy` or `pool` modes
- Reduce worker count
- Reduce packet buffer size (`-pbuf`)

**Packet Corruption/Invalid Data:**
- If using `nocopy`, ensure buffers aren't being reused
- Switch to `default` mode for safety

**Slow Processing:**
- Try `pool` mode for better performance
- Increase worker count (`-workers`)
- Disable features you don't need (`-comp false`, `-payload false`)

**Concurrency Issues:**
- Never use `lazy` mode with multiple workers
- Use `default` or `pool` for concurrent processing

## References

- [gopacket Documentation](https://pkg.go.dev/github.com/gopacket/gopacket)
- [gopacket DecodeOptions](https://pkg.go.dev/github.com/gopacket/gopacket#DecodeOptions)
- [NETCAP Packet Processing](EXCLUDE_DECODER_BEHAVIOR.md)
- [NETCAP Performance](PERFORMANCE_ENHANCEMENTS.md)

## See Also

- [Live Collection](live-collection.md) - Live packet capture configuration
- [Configuration](configuration.md) - General configuration options
- [Workers](workers.md) - Worker pool configuration
- [Performance Tracking](PERFORMANCE_TRACKING.md) - Performance monitoring

