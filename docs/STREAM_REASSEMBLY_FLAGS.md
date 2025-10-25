# Stream Reassembly Command-Line Flags

Quick reference for all stream reassembly configuration flags.

---

## Available Flags

### `-max-stream-bytes`
**Type**: int  
**Default**: 10485760 (10MB)  
**Description**: Maximum number of bytes to reassemble per stream direction

**Examples**:
```bash
# Use default (10MB)
net capture -read traffic.pcap

# Set to 50MB
net capture -read traffic.pcap -max-stream-bytes 52428800

# Unlimited (use with caution)
net capture -read traffic.pcap -max-stream-bytes 0

# Protocol headers only (64KB)
net capture -read traffic.pcap -max-stream-bytes 65536
```

**When to use**: 
- ✅ Always recommended as primary memory protection
- ✅ Limit processing of large file transfers
- ✅ Capture only initial protocol data

---

### `-max-buffered-pages-per-conn`
**Type**: int  
**Default**: 0 (unlimited)  
**Description**: Maximum pages to buffer per connection for out-of-order packets  
**Page size**: ~1900 bytes

**Examples**:
```bash
# Allow 100 pages (~190KB) per connection
net capture -read traffic.pcap -max-buffered-pages-per-conn 100

# Strict limit for constrained systems
net capture -iface eth0 -max-buffered-pages-per-conn 50

# Unlimited (default)
net capture -read traffic.pcap -max-buffered-pages-per-conn 0
```

**When to use**:
- ✅ Connections with severe packet reordering
- ✅ Prevent single connection from hogging memory
- ⚠️ May create gaps under packet loss

---

### `-max-buffered-pages-total`
**Type**: int  
**Default**: 0 (unlimited)  
**Description**: Maximum total pages to buffer across all connections  
**Page size**: ~1900 bytes

**Examples**:
```bash
# Limit total to 10,000 pages (~19MB globally)
net capture -read traffic.pcap -max-buffered-pages-total 10000

# Strict limit for embedded systems
net capture -iface eth0 -max-buffered-pages-total 1000

# Unlimited (default)
net capture -read traffic.pcap -max-buffered-pages-total 0
```

**When to use**:
- ✅ Processing many concurrent connections
- ✅ System-wide memory constraints
- ✅ Prevent memory exhaustion under load

---

## Common Configurations

### Default (Recommended)
```bash
net capture -read traffic.pcap
# MaxStreamBytes: 10MB
# MaxBufferedPagesPerConnection: unlimited
# MaxBufferedPagesTotal: unlimited
```

### Memory-Constrained System
```bash
net capture -iface eth0 \
  -max-stream-bytes 5242880 \
  -max-buffered-pages-per-conn 50 \
  -max-buffered-pages-total 1000
```

### High-Volume Production
```bash
net capture -iface eth0 \
  -max-stream-bytes 52428800 \
  -max-buffered-pages-total 100000
```

### Protocol Analysis Only
```bash
net capture -read traffic.pcap \
  -max-stream-bytes 65536 \
  -max-buffered-pages-per-conn 10
```

---

## Configuration File

Add to `net.capture.conf`:

```conf
# Maximum bytes per stream direction (0 = unlimited, default = 10MB)
max-stream-bytes 10485760

# Maximum pages per connection for out-of-order packets (0 = unlimited)
max-buffered-pages-per-conn 0

# Maximum total pages across all connections (0 = unlimited)
max-buffered-pages-total 0
```

---

## Quick Decision Guide

**Question**: What limit should I use?

### Start Here
1. **Set `-max-stream-bytes 10485760`** (default is good for most cases)
2. Leave other limits at 0 (unlimited)
3. Monitor memory usage

### If Memory Issues Persist
1. Lower `-max-stream-bytes` to 5MB or less
2. Add `-max-buffered-pages-total` based on your RAM
3. Only add `-max-buffered-pages-per-conn` if specific connections are problematic

### If Packet Reordering Issues
1. Increase `-max-buffered-pages-per-conn` to 100-500
2. Add `-max-buffered-pages-total` for global protection
3. Check network quality

---

## See Also

- [STREAM_REASSEMBLY_LIMITS.md](STREAM_REASSEMBLY_LIMITS.md) - Comprehensive documentation
- [MAX_STREAM_BYTES.md](MAX_STREAM_BYTES.md) - MaxStreamBytes detailed guide
- [MAX_STREAM_BYTES_REVIEW.md](MAX_STREAM_BYTES_REVIEW.md) - Implementation review

