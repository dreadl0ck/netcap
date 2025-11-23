# Credential Harvester Max Bytes Limit

## Overview

The credential harvesters in Netcap process network stream data to extract authentication credentials. To prevent performance issues when processing large data streams (e.g., file transfers, database dumps, video streaming), the amount of data processed by each harvester is limited by the configurable `HarvesterBannerSize` parameter.

## Problem Statement

Without a limit, credential harvesters would process entire network streams, which could lead to:

1. **Excessive CPU usage** - Running regex patterns and parsers on megabytes/gigabytes of data
2. **Memory exhaustion** - Buffering large amounts of data for pattern matching
3. **Performance degradation** - Slowing down the entire capture pipeline
4. **False positives** - Finding credential-like patterns in binary file data

## Solution

The `HarvesterBannerSize` configuration parameter limits the maximum number of bytes from each bi-directional stream conversation that is passed to credential harvesters.

### How It Works

1. **Stream Data Collection**: As packets are reassembled into TCP/UDP streams, the raw conversation data is collected.

2. **Banner Creation**: Before passing data to harvesters, the `createBannerFromConversation()` function extracts only the first `HarvesterBannerSize` bytes from the conversation.

3. **Harvester Processing**: Each credential harvester receives at most `HarvesterBannerSize` bytes, regardless of the actual stream size.

4. **Safety Check**: `RunHarvesters()` includes an additional safeguard to truncate any oversized banners.

### Configuration

#### Default Value
- **512 bytes** (set in `DefaultConfig`)

#### Recommended Range
- **Minimum**: 256 bytes - May miss credentials in protocols with longer handshakes
- **Default**: 512 bytes - Good balance for most use cases
- **Medium**: 2048 bytes - For protocols with longer authentication sequences
- **Maximum**: 8192 bytes - For complex authentication flows, but may impact performance

#### Configuration Methods

##### 1. Command Line Flag
```bash
net capture -iface eth0 -hbsize 2048
```

##### 2. Environment Variable
```bash
export NC_HBSIZE=2048
net capture -iface eth0
```

##### 3. Configuration File
```yaml
decoder:
  harvester_banner_size: 2048
```

##### 4. Programmatic Configuration
```go
import decoderconfig "github.com/dreadl0ck/netcap/decoder/config"

decoderconfig.Instance.HarvesterBannerSize = 2048
```

## Performance Impact

### Test Results

Based on our test suite (`TestPerformanceWithLargeStreams`):

- **Input Stream Size**: 1 MB
- **Configured Limit**: 512 bytes
- **Processing Time**: < 100 microseconds
- **Memory Usage**: ~512 bytes (instead of 1 MB)

This demonstrates that even when processing very large streams, the performance impact is minimal due to the truncation.

### Scalability

With the max bytes limit:
- ✅ Processing time is constant regardless of stream size
- ✅ Memory usage is bounded and predictable
- ✅ No performance degradation on file transfers
- ✅ Can handle thousands of concurrent streams

Without the limit:
- ❌ Processing time increases linearly with stream size
- ❌ Memory usage can grow unbounded
- ❌ Performance degrades significantly with large transfers
- ❌ Limited scalability

## Protocol Considerations

Different protocols have different credential patterns at different offsets:

| Protocol | Typical Credential Location | Recommended Min Size |
|----------|----------------------------|---------------------|
| FTP      | First 200 bytes            | 256 bytes          |
| HTTP Basic Auth | First 500 bytes     | 512 bytes          |
| HTTP Digest | First 800 bytes         | 1024 bytes         |
| SMTP     | First 400 bytes            | 512 bytes          |
| Telnet   | First 300 bytes            | 512 bytes          |
| IMAP     | First 600 bytes            | 1024 bytes         |
| POP3     | First 300 bytes            | 512 bytes          |
| NTLMSSP  | First 1500 bytes           | 2048 bytes         |
| Kerberos | First 1500 bytes           | 2048 bytes         |
| LDAP     | First 500 bytes            | 1024 bytes         |
| PostgreSQL | First 1000 bytes         | 1024 bytes         |
| MySQL    | First 800 bytes            | 1024 bytes         |
| MongoDB  | First 1200 bytes           | 2048 bytes         |
| Redis    | First 200 bytes            | 256 bytes          |
| VNC      | First 300 bytes            | 512 bytes          |

## Debugging

### Enable Debug Logging

When `Debug` mode is enabled, the system logs when banner data is truncated:

```go
decoderconfig.Instance.Debug = true
```

Example log output:
```
DEBUG: harvester banner truncated - totalSize: 10485760, processedSize: 512, maxSize: 512
```

### Testing Different Limits

Use the `TestConfigurableLimit` test to verify different limit values:

```bash
go test -v -run TestConfigurableLimit
```

### Checking if Credentials Are Being Missed

If you suspect credentials are being missed due to the limit being too small:

1. Increase `HarvesterBannerSize` temporarily:
   ```bash
   net capture -iface eth0 -hbsize 4096 -debug
   ```

2. Monitor the debug logs for truncation messages

3. Check if more credentials are detected

4. Adjust the limit based on your findings

## Implementation Details

### Code Flow

```
Packet Capture
    ↓
Stream Reassembly
    ↓
createBannerFromConversation() 
    - Extracts first N bytes (N = HarvesterBannerSize)
    - Logs truncation in debug mode
    ↓
RunHarvesters()
    - Safety check: re-truncate if needed
    - Pass truncated banner to each harvester
    ↓
Individual Harvesters
    - Process only the truncated banner
    - Extract credentials using regex/parsing
    ↓
WriteCredentials()
    - Deduplicate and write to disk
```

### Key Files

- **Config Definition**: `decoder/config/config.go`
- **Banner Creation**: `decoder/stream/utils/save_conversation.go`
- **Harvester Entry Point**: `decoder/stream/credentials/harvester.go`
- **Tests**: `decoder/stream/credentials/max_bytes_test.go`
- **CLI Flags**: `cmd/capture/flags.go`

## Best Practices

### 1. Start with Default Value
The default 512 bytes works well for most common protocols. Don't increase unless necessary.

### 2. Monitor False Negatives
If you're not detecting credentials you expect to find:
- Enable debug mode to see truncation logs
- Gradually increase `HarvesterBannerSize`
- Test with known credential captures

### 3. Consider Your Environment
- **High-security networks**: Use larger values (2048-4096) to catch complex auth flows
- **High-throughput networks**: Use smaller values (256-512) for better performance
- **Mixed environments**: Use default (512) and monitor results

### 4. Balance Performance vs. Detection
- More bytes = better detection rate, higher CPU/memory usage
- Fewer bytes = better performance, might miss some credentials

### 5. Test Before Production
Always test your configuration with representative traffic before deploying to production.

## Troubleshooting

### Issue: Credentials Not Being Detected

**Possible Causes:**
1. `HarvesterBannerSize` is too small for the protocol
2. Credentials appear later in the stream
3. Protocol uses encryption (credentials won't be visible)

**Solutions:**
1. Increase `HarvesterBannerSize` to 2048 or 4096
2. Enable debug mode and check truncation logs
3. Capture sample traffic and analyze manually

### Issue: High CPU/Memory Usage

**Possible Causes:**
1. `HarvesterBannerSize` is too large
2. Too many concurrent streams
3. Regular expressions are too complex

**Solutions:**
1. Reduce `HarvesterBannerSize` to 256 or 512
2. Use `StopAfterHarvesterMatch: true` (default)
3. Profile with `memprofile` flag to identify bottlenecks

### Issue: Performance Degradation on Large Transfers

**Verify Configuration:**
```bash
# Check current setting
echo $NC_HBSIZE

# Should be <= 1024 for high-performance scenarios
net capture -iface eth0 -hbsize 512
```

If performance is still poor, the issue is likely elsewhere in the pipeline, not the harvesters.

## FAQ

**Q: What happens if I set HarvesterBannerSize to 0?**
A: The code will still work but won't process any data, so no credentials will be detected.

**Q: Can I set different limits for different protocols?**
A: Not currently. The limit applies globally to all harvesters. This is a potential future enhancement.

**Q: Does this affect service detection?**
A: No. Service detection uses a separate `BannerSize` parameter and is independent of credential harvesting.

**Q: Will increasing the limit help with encrypted protocols?**
A: No. Encrypted protocols (HTTPS, SSH, TLS) don't expose credentials in the stream, regardless of the buffer size.

**Q: What's the performance impact of increasing from 512 to 4096?**
A: Minimal for most scenarios. The main impact is memory usage (8x increase per stream). CPU impact depends on the complexity of regex patterns in harvesters.

## Future Enhancements

Potential improvements to consider:

1. **Per-Protocol Limits**: Allow different limits for different protocols
2. **Adaptive Sizing**: Automatically adjust based on detected protocol
3. **Stream Sampling**: Sample bytes from throughout the stream, not just the beginning
4. **Compression-Aware**: Handle compressed streams more intelligently
5. **Metrics**: Export metrics on truncation frequency and credential detection rates

## References

- Main Documentation: `docs/README.md`
- Credential Harvesters: `decoder/stream/credentials/README.md`
- Configuration Guide: `docs/configuration.md`
- Performance Tuning: `docs/performance.md`

## Version History

- **v0.7.6+**: Added comprehensive max bytes limit with tests and documentation
- **Earlier versions**: Had implicit limits but not well documented or tested

