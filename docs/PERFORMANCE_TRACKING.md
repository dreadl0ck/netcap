# Performance Tracking

## Overview

Netcap now includes comprehensive performance tracking that measures the processing speed of various components and generates a detailed performance report for each execution.

## What is Tracked

The performance tracking system monitors:

1. **Overall Statistics**
   - Total packets processed
   - Total bytes written
   - Overall throughput (packets/sec and Mbps)
   - Processing duration

2. **TCP Reassembly Performance**
   - Number of packets reassembled
   - Total and average time per packet
   - Reassembly rate (packets/sec)

3. **Deep Packet Inspection (DPI) Performance** (when enabled)
   - Number of DPI calls
   - Total and average time per call
   - DPI call rate (calls/sec)

4. **Database/Resolver Performance**
   - **DNS**: Reverse DNS lookups
   - **Geolocation**: IP to location/ASN mapping
   - **MAC**: MAC address to manufacturer lookups
   - **Service**: Port to service name resolution
   - **Ja3**: TLS fingerprint lookups
   
   For each resolver:
   - Number of lookups performed
   - Cache hits (when applicable)
   - Hit rate percentage
   - Average and total lookup time

5. **Decoder Performance** (by decoder type)
   - **GoPacket Decoders**: Built-in protocol decoders (Ethernet, IPv4, TCP, etc.)
   - **Custom Decoders**: Custom packet decoders (DeviceProfile, Connection, TLS*, etc.)
   - **Stream Decoders**: Stream-based decoders (HTTP, SMTP, SSH)
   - **Abstract Decoders**: High-level decoders (Service, Exploit, Software, etc.)
   
   For each decoder:
   - Number of invocations
   - Number of records produced
   - Average processing time per invocation
   - Total processing time

6. **Disk I/O Performance**
   - Number of write operations per file
   - Bytes written per file
   - Time spent writing
   - Overall disk I/O throughput (MB/s)

## Output Location

The performance report is written to `performance.log` in the same output directory as other audit record files.

Example: If you run `net capture -read input.pcap -out /tmp/netcap-output`, the report will be at `/tmp/netcap-output/performance.log`.

## Sample Output

```
================================================================================
NETCAP PERFORMANCE REPORT
================================================================================
Generated: 2025-10-25T15:14:19+02:00
Duration: 2.385953042s

OVERALL STATISTICS
--------------------------------------------------------------------------------
Total Packets:        21933
Total Bytes:          1.3 MB (1260714 bytes)
Throughput:           9192.55 packets/sec, 4.23 Mbps

TCP REASSEMBLY PERFORMANCE
--------------------------------------------------------------------------------
Packets Reassembled:  21933
Total Time:           393.177268ms
Average per Packet:   17.926µs
Reassembly Rate:      55784.89 packets/sec

DEEP PACKET INSPECTION (DPI) PERFORMANCE
--------------------------------------------------------------------------------
DPI Calls:            1234
Total Time:           45.2ms
Average per Call:     36.6µs
DPI Call Rate:        27295.92 calls/sec

DATABASE/RESOLVER PERFORMANCE
--------------------------------------------------------------------------------
Resolver                            Lookups   Cache Hits     Hit Rate        Avg Time      Total Time
--------                            -------   ----------     --------        --------      ----------
MAC                                      65            0         0.0%         2.835µs       184.292µs
Service                                 372            0         0.0%            53ns        19.841µs
Geolocation                             285            0         0.0%            39ns        11.251µs
Ja3                                      22            0         0.0%            71ns         1.582µs

GOPACKET DECODER PERFORMANCE
--------------------------------------------------------------------------------
Decoder                               Count      Records        Avg Time      Total Time
-------                               -----      -------        --------      ----------
Ethernet                              21933        21933         28.62µs    627.732172ms
UDP                                   13584        13584        24.909µs    338.377396ms
IPv4                                  14866        14866        20.266µs    301.284162ms
...

DISK I/O PERFORMANCE
--------------------------------------------------------------------------------
File                                         Writes           Bytes      Total Time
----                                         ------           -----      ----------
Ethernet                                      21933          1.2 MB      6.709429ms
IPv4                                          14866          1.0 MB      5.572296ms
...
----                                         ------           -----      ----------
TOTAL                                         77404          4.8 MB      27.81701ms

Disk I/O Throughput:  1380.70 MB/s

================================================================================
```

## Use Cases

### 1. Performance Benchmarking
Compare performance across different:
- Hardware configurations
- Network traffic patterns
- Decoder configurations
- File formats (CSV vs Protobuf)

### 2. Bottleneck Identification
Identify performance bottlenecks by examining:
- Which decoders take the most time
- Disk I/O vs processing time ratios
- Reassembly performance impact

### 3. Optimization Tracking
Monitor improvements over time:
- Track performance changes between versions
- Validate optimization efforts
- Ensure no performance regressions

### 4. Capacity Planning
Determine processing capacity:
- Maximum sustainable packet rate
- Storage I/O requirements
- Memory and CPU requirements for specific traffic patterns

## Implementation Details

### Architecture

The performance tracking system consists of:

1. **performance.Tracker** (`performance/tracker.go`)
   - Central tracking structure
   - Thread-safe metric recording
   - Report generation

2. **Integration Points**
   - `collector/collector.go`: Tracker initialization
   - `collector/worker.go`: Per-packet timing
   - `collector/cleanup.go`: Report generation
   - `io/*.go`: Disk I/O timing
   - `decoder/config/config.go`: Config propagation

3. **Minimal Overhead**
   - Uses `time.Now()` and `time.Since()` for timing
   - Atomic operations for thread safety
   - Metrics aggregated, not stored per-operation
   - Report generated only at shutdown

### Accuracy Considerations

- Timing includes all processing overhead
- Disk I/O times may include buffering effects
- Multi-threaded processing affects individual operation times
- Results are most meaningful for relative comparisons

## Future Enhancements

Potential improvements:
- Real-time performance monitoring via HTTP endpoint
- Performance alerts for degraded performance
- Historical performance tracking
- Prometheus metrics integration (already partially implemented)
- Per-stream/connection performance metrics

