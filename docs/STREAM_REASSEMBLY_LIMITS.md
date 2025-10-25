# Stream Reassembly Limits

## Overview

Netcap provides three complementary configuration options to control memory usage and performance during TCP stream reassembly. Each serves a different purpose and can be used independently or in combination.

---

## The Three Limits

### 1. MaxStreamBytes (Primary Protection)
**Controls**: Total bytes reassembled per stream direction  
**Scope**: Per stream direction (client→server and server→client independently)  
**Unit**: Bytes  
**Default**: 10485760 (10MB)  
**Applies to**: All data (in-order + out-of-order)

### 2. MaxBufferedPagesPerConnection
**Controls**: Out-of-order packet buffering per connection  
**Scope**: Per connection direction  
**Unit**: Pages (~1900 bytes each)  
**Default**: 0 (unlimited)  
**Applies to**: Only out-of-order data waiting for missing packets

### 3. MaxBufferedPagesTotal  
**Controls**: Out-of-order packet buffering globally  
**Scope**: All connections across entire assembler  
**Unit**: Pages (~1900 bytes each)  
**Default**: 0 (unlimited)  
**Applies to**: Only out-of-order data waiting for missing packets

---

## Quick Reference

| Option | Flag | Default | Purpose |
|--------|------|---------|---------|
| **MaxStreamBytes** | `-max-stream-bytes` | 10MB | Limit total stream size |
| **MaxBufferedPagesPerConnection** | `-max-buffered-pages-per-conn` | 0 (unlimited) | Limit per-connection reorder buffer |
| **MaxBufferedPagesTotal** | `-max-buffered-pages-total` | 0 (unlimited) | Limit global reorder buffer |

---

## Detailed Explanations

### MaxStreamBytes - Total Stream Size Limit

**What it does**: Limits the cumulative number of bytes that can be reassembled from a single TCP stream direction before the stream is closed.

**When to use**:
- ✅ Prevent memory exhaustion from large file transfers
- ✅ Limit processing time for very long connections
- ✅ Capture only protocol headers and initial payload
- ✅ **Primary memory protection** (recommended for all deployments)

**Behavior when exceeded**:
```
Stream receives MaxStreamBytes bytes
→ half.closed = true
→ Further packets on that direction are rejected
→ Stream stops processing
→ No gaps created, clean cutoff
→ Connection stays in pool (prevents recreation/bypass)
```

**Important: Recreation Protection**
- When a stream direction hits `MaxStreamBytes`, it sets `half.closed = true`
- The connection **remains in the stream pool** and is **NOT removed**
- Future packets on the closed direction are rejected immediately
- The connection **cannot be recreated** to bypass the limit
- Removal only occurs when **both directions** are closed AND `ReassemblyComplete()` returns true
- This prevents malicious or buggy traffic from bypassing the limit by reconnecting

**Example**:
```bash
# Limit each stream direction to 10MB (default)
net capture -read traffic.pcap -max-stream-bytes 10485760

# Capture only first 1MB for protocol inspection
net capture -iface eth0 -max-stream-bytes 1048576

# Unlimited (use with caution!)
net capture -read traffic.pcap -max-stream-bytes 0
```

**Impact**:
- Minimal overhead (one integer comparison per packet)
- Affects both in-order and out-of-order data
- Clean stream termination

---

### MaxBufferedPagesPerConnection - Per-Connection Reorder Buffer

**What it does**: Limits how many pages can be buffered while waiting for out-of-order packets on a **single connection**.

**When to use**:
- ✅ Connections experiencing severe packet reordering
- ✅ Prevent single connection from hogging memory
- ✅ Graceful degradation under packet loss

**Behavior when exceeded**:
```
Connection buffers MaxBufferedPages out-of-order packets
→ action.queue = false (stop queuing)
→ Flush oldest buffered packet immediately
→ Creates gaps if packets truly missing
→ Connection continues processing
```

**Example**:
```bash
# Allow up to 100 pages (~190KB) per connection
net capture -read traffic.pcap -max-buffered-pages-per-conn 100

# Stricter limit for memory-constrained systems
net capture -iface eth0 -max-buffered-pages-per-conn 50
```

**Visual Example**:
```
Packets received: 1, 2, 3, 100, 101, 102, ..., 110
MaxBufferedPagesPerConnection = 10

Buffered: 100-109 (waiting for 4-99)
Packet 110 arrives → Limit reached!
→ Flush packet 100 even though 4-99 are missing
→ Stream sees: 1, 2, 3, [GAP], 100, [GAP], 101, ...
```

**Impact**:
- Only affects out-of-order packets
- Creates gaps under packet loss
- Connection remains active

---

### MaxBufferedPagesTotal - Global Reorder Buffer

**What it does**: Limits the **total number of pages** buffered across **ALL connections** in an assembler.

**When to use**:
- ✅ Processing hundreds or thousands of connections
- ✅ System-wide memory constraints
- ✅ Multi-tenant or shared infrastructure
- ✅ Prevent memory exhaustion under DDoS

**Behavior when exceeded**:
```
Total buffered pages across all connections ≥ MaxBufferedPagesTotal
→ All new out-of-order packets flushed immediately
→ Affects all connections, not just one
→ Global degradation mode
```

**Example**:
```bash
# Limit total buffering to ~19MB across all connections
net capture -read traffic.pcap -max-buffered-pages-total 10000

# Very strict limit for embedded systems
net capture -iface eth0 -max-buffered-pages-total 1000
```

**Visual Example**:
```
100 active connections
Total buffered pages: 9,995
MaxBufferedPagesTotal: 10,000

Any connection receives out-of-order packet:
→ Would exceed global limit
→ Packet flushed immediately on ALL connections
→ Global memory cap enforced
```

**Impact**:
- Affects all connections globally
- Only impacts out-of-order scenarios
- System-wide memory protection

---

## Understanding Pages

**What is a page?**
- Buffer unit holding ~1900 bytes of TCP data
- Used only for out-of-order packets
- Stored in doubly-linked list per connection
- Recycled via pageCache to avoid allocations

**Memory calculation**:
```
10 buffered pages = ~19 KB
100 buffered pages = ~190 KB  
1,000 buffered pages = ~1.9 MB
10,000 buffered pages = ~19 MB
```

**Important**: Pages are only allocated for **out-of-order** data. In-order data passes through directly without buffering.

---

## Configuration Examples

### Scenario 1: Default (Recommended)
```bash
net capture -read traffic.pcap
# MaxStreamBytes: 10MB (prevents huge transfers)
# MaxBufferedPages*: unlimited (handles normal reordering)
```
✅ Best for most use cases  
✅ Protects against large transfers  
✅ Handles packet reordering gracefully

### Scenario 2: Memory-Constrained System
```bash
net capture -iface eth0 \
  -max-stream-bytes 5242880 \               # 5MB per stream
  -max-buffered-pages-per-conn 50 \         # ~95KB per connection
  -max-buffered-pages-total 1000            # ~1.9MB total
```
✅ Tight memory control  
✅ Three layers of protection  
✅ Suitable for embedded/edge devices

### Scenario 3: High-Volume Production
```bash
net capture -iface eth0 \
  -max-stream-bytes 52428800 \              # 50MB per stream
  -max-buffered-pages-total 100000          # ~190MB total buffer
```
✅ Large stream capture  
✅ Global memory ceiling  
✅ Handles 1000s of connections

### Scenario 4: Protocol Analysis Only
```bash
net capture -read traffic.pcap \
  -max-stream-bytes 65536 \                 # 64KB per stream
  -max-buffered-pages-per-conn 10           # Minimal buffering
```
✅ Capture headers only  
✅ Minimal memory usage  
✅ Fast processing

### Scenario 5: Unlimited (Testing/Development)
```bash
net capture -read small.pcap \
  -max-stream-bytes 0 \                     # No limit
  -max-buffered-pages-per-conn 0 \          # No limit
  -max-buffered-pages-total 0               # No limit
```
⚠️ Use with caution  
⚠️ Can exhaust memory  
⚠️ Only for known small captures

---

## Comparison Matrix

| Feature | MaxStreamBytes | MaxBufferedPages* |
|---------|---------------|-------------------|
| **Data Type** | All (in-order + out-of-order) | Only out-of-order |
| **Measurement** | Actual bytes | Pages (~1900 bytes) |
| **Action on Limit** | Close stream | Flush oldest buffered data |
| **Creates Gaps** | No (clean cutoff) | Yes (under packet loss) |
| **Overhead** | Minimal | Minimal |
| **Connection After** | Stops processing | Continues processing |
| **Use Frequency** | Always recommended | Optional, as needed |

---

## How They Work Together

### Example: All Three Limits in Action

```bash
net capture -read traffic.pcap \
  -max-stream-bytes 10485760 \              # 10MB total per direction
  -max-buffered-pages-per-conn 100 \        # 100 pages per connection
  -max-buffered-pages-total 10000           # 10000 pages globally
```

**Scenario**: Processing 100 concurrent connections with packet reordering

1. **MaxBufferedPagesTotal** (19MB global):
   - Prevents system-wide memory exhaustion
   - Affects all connections when total pages > 10,000

2. **MaxBufferedPagesPerConnection** (190KB per connection):
   - Limits individual connection reorder buffer
   - Forces flush when connection pages > 100

3. **MaxStreamBytes** (10MB per direction):
   - Ultimate protection per stream
   - Closes stream when total bytes > 10MB

**Result**: Three-layer memory protection with graceful degradation.

---

## Monitoring and Debugging

### Enable Debug Mode
```bash
net capture -read traffic.pcap -debug -reassembly-debug
```

### Debug Output Examples

**MaxStreamBytes hit**:
```
hit max stream bytes: 10485760 >= 10485760, closing half connection
```

**MaxBufferedPages* hit**:
```
hit max buffer size: &{MaxBufferedPagesPerConnection:100 MaxBufferedPagesTotal:10000}, 101, 9854
```

### Prometheus Metrics (if enabled)
```bash
net capture -iface eth0 -metrics localhost:2112
```
Exposes metrics for monitoring stream reassembly behavior.

---

## Configuration File

Add to `net.capture.conf`:

```conf
# Stream size limit (bytes)
max-stream-bytes 10485760

# Per-connection reorder buffer (pages)
max-buffered-pages-per-conn 0

# Global reorder buffer (pages)
max-buffered-pages-total 0
```

---

## Programmatic Configuration

```go
import (
    "github.com/dreadl0ck/netcap/collector"
    "github.com/dreadl0ck/netcap/decoder/config"
)

cfg := collector.Config{
    DecoderConfig: &config.Config{
        // Stream size limit
        MaxStreamBytes: 10485760, // 10MB
        
        // Per-connection reorder buffer
        MaxBufferedPagesPerConnection: 100, // ~190KB
        
        // Global reorder buffer  
        MaxBufferedPagesTotal: 10000, // ~19MB
    },
}

c := collector.New(cfg)
```

---

## Best Practices

### ✅ Recommended

1. **Always set MaxStreamBytes** to prevent memory issues
2. **Leave MaxBufferedPages* unlimited** unless you have specific reordering issues
3. **Start with defaults** and adjust based on monitoring
4. **Use MaxBufferedPagesTotal** for high-concurrency scenarios
5. **Test configuration** with representative traffic

### ⚠️ Cautions

1. **Don't set all limits to 0** (unlimited) in production
2. **Don't set limits too low** (causes excessive gaps)
3. **Monitor for gaps** when using page limits
4. **Consider packet loss** in your environment
5. **Account for peak concurrent connections**

---

## Troubleshooting

### Problem: Gaps in reassembled streams
**Cause**: MaxBufferedPages* limits too low or severe packet loss  
**Solution**: Increase page limits or check network quality

### Problem: Memory exhaustion
**Cause**: No limits set or limits too high  
**Solution**: Enable MaxStreamBytes (primary) and consider page limits

### Problem: Streams cut off too early
**Cause**: MaxStreamBytes too low  
**Solution**: Increase MaxStreamBytes or set to 0 for specific analysis

### Problem: Poor performance under load
**Cause**: Too much buffering  
**Solution**: Reduce MaxStreamBytes, add page limits

---

## Performance Impact

| Configuration | Memory Usage | CPU Impact | Suitable For |
|---------------|-------------|------------|--------------|
| All unlimited | ⚠️ High | Low | Small captures only |
| Default (MaxStreamBytes: 10MB) | ✅ Moderate | Low | Most deployments |
| Strict limits on all | ✅ Low | Moderate | Constrained systems |
| Only MaxStreamBytes | ✅ Moderate | Low | **Recommended** ✅ |

---

## Summary

**For most users**: The default configuration (MaxStreamBytes: 10MB, others unlimited) provides the best balance of memory protection and functionality.

**The three-layer approach**:
1. **MaxStreamBytes**: Primary protection against large streams (10MB default) ✅
2. **MaxBufferedPagesPerConnection**: Optional per-connection reorder limit
3. **MaxBufferedPagesTotal**: Optional global memory ceiling

**Key principle**: Start with defaults, monitor behavior, adjust only if needed.

