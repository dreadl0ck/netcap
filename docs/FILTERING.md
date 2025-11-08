# Expression-Based Filtering in NETCAP

NETCAP supports powerful expression-based filtering of audit records using the [expr-lang](https://expr-lang.org) expression language. This allows you to selectively output audit records based on complex conditions.

## Table of Contents

- [Overview](#overview)
- [Expression Syntax](#expression-syntax)
- [Available Fields](#available-fields)
- [Helper Functions](#helper-functions)
- [Usage Examples](#usage-examples)
- [Performance Considerations](#performance-considerations)

## Overview

Filtering in NETCAP allows you to:

- **Reduce output size** by only displaying records matching specific criteria
- **Focus analysis** on relevant traffic patterns
- **Extract specific conversations** from large capture files
- **Identify suspicious activities** based on traffic characteristics

Filters are available in the `net dump` command and can be applied to any audit record type.

## Expression Syntax

Expressions use a C-like syntax with support for:

- **Comparison operators**: `==`, `!=`, `<`, `>`, `<=`, `>=`
- **Logical operators**: `&&` (AND), `||` (OR), `!` (NOT)
- **Arithmetic operators**: `+`, `-`, `*`, `/`, `%`
- **String operations**: `contains()`, `startsWith()`, `endsWith()`
- **Regular expressions**: `matches()`
- **Membership testing**: `in`

### Basic Examples

```bash
# Simple equality
DstPort == 443

# Logical AND
SrcPort == 80 && DstPort == 443

# Logical OR
DstPort == 80 || DstPort == 443 || DstPort == 8080

# Range comparison
DstPort >= 1000 && DstPort <= 2000

# Negation
!(DstPort == 80)
```

## Available Fields

Fields available in expressions depend on the audit record type. All fields from the protobuf definition are accessible directly by name.

### Common Fields (Most Record Types)

- `Timestamp` (int64) - Unix timestamp in nanoseconds
- `SrcIP` (string) - Source IP address
- `DstIP` (string) - Destination IP address
- `SrcPort` (int) - Source port number
- `DstPort` (int) - Destination port number

### TCP Records

- `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`, `NS` (bool) - TCP flags
- `SeqNum`, `AckNum` (uint32) - Sequence and acknowledgment numbers
- `Window` (int32) - Window size
- `PayloadSize` (int32) - Size of payload data

### UDP Records

- `Length` (int32) - UDP packet length
- `Checksum` (int32) - UDP checksum
- `PayloadSize` (int32) - Size of payload data

### HTTP Records

- `Method` (string) - HTTP method (GET, POST, etc.)
- `Host` (string) - HTTP Host header
- `UserAgent` (string) - User-Agent header
- `StatusCode` (int32) - HTTP response status code
- `ContentLength` (int64) - Content-Length header value
- `URL` (string) - Request URL

### DNS Records

- `Questions` (array) - DNS questions
- `Answers` (array) - DNS answers
- `Authorities` (array) - Authority records
- `Additionals` (array) - Additional records

To see all available fields for a specific audit record type, use:

```bash
net dump -read <file>.ncap.gz -fields
```

## Helper Functions

NETCAP provides helper functions for common filtering operations:

### Network Functions

#### `InSubnet(ip string, cidr string) bool`

Check if an IP address is within a CIDR subnet.

```bash
InSubnet(SrcIP, "192.168.0.0/16")
```

#### `IsPrivateIP(ip string) bool`

Check if an IP is in a private address range (RFC 1918, loopback, link-local).

```bash
IsPrivateIP(SrcIP)
```

#### `IsPublicIP(ip string) bool`

Check if an IP is a public (non-private) address.

```bash
IsPublicIP(DstIP)
```

#### `ParsePort(port string) int`

Convert a port string to an integer.

```bash
ParsePort("443") == 443
```

#### `PortInRange(port int, start int, end int) bool`

Check if a port is within a range (inclusive).

```bash
PortInRange(DstPort, 1024, 65535)
```

### Time Functions

#### `TimeInRange(ts int64, start int64, end int64) bool`

Check if a timestamp is within a range.

```bash
TimeInRange(Timestamp, 1609459200000000000, 1640995200000000000)
```

#### `DurationSince(ts int64) int64`

Get the duration in nanoseconds since a timestamp.

```bash
DurationSince(Timestamp) < 3600000000000  # Less than 1 hour ago
```

#### `FormatTime(ts int64, format string) string`

Format a timestamp using Go's time format layout.

```bash
FormatTime(Timestamp, "2006-01-02 15:04:05")
```

### String Functions

#### `ContainsAny(str string, substrs []string) bool`

Check if a string contains any of the provided substrings as a substring (not exact match).
For exact matches with array literals, use the `in` operator instead.

```bash
# For substring matching (e.g., "curl/7.68.0" contains "curl")
# Note: Use the 'in' operator for exact matches with arrays
UserAgent in ["curl", "wget", "python"]

# For programmatic use with a string slice:
# ContainsAny can be called with a variable
```

#### `MatchesPattern(str string, pattern string) bool`

Check if a string matches a regular expression pattern.

```bash
MatchesPattern(URL, ".*\\.php\\?.*")
```

## Usage Examples

### Filter by Port

Show only HTTPS traffic:

```bash
net dump -read TCP.ncap.gz -filter "DstPort == 443"
```

### Filter by IP Range

Show traffic to/from a specific subnet:

```bash
net dump -read IPv4.ncap.gz -filter "InSubnet(SrcIP, '10.0.0.0/8') || InSubnet(DstIP, '10.0.0.0/8')"
```

### Filter Private to Public Traffic

Identify outbound traffic from private networks:

```bash
net dump -read IPv4.ncap.gz -filter "IsPrivateIP(SrcIP) && IsPublicIP(DstIP)"
```

### Filter HTTP POST Requests

Show only HTTP POST requests:

```bash
net dump -read HTTP.ncap.gz -filter "Method == 'POST'"
```

### Filter Large Uploads

Detect large HTTP uploads (>10MB):

```bash
net dump -read HTTP.ncap.gz -filter "Method == 'POST' && ReqContentLength > 10000000"
```

### Filter Suspicious User-Agents

Identify automated tools (exact match):

```bash
net dump -read HTTP.ncap.gz -filter "UserAgent in ['curl', 'wget', 'python', 'scanner']"
```

### Filter TCP SYN Scans

Detect potential SYN scan attempts:

```bash
net dump -read TCP.ncap.gz -filter "SYN && !ACK"
```

### Filter by Time Range

Show traffic within a specific time window:

```bash
net dump -read TCP.ncap.gz -filter "Timestamp >= 1609459200000000000 && Timestamp <= 1609545600000000000"
```

### Complex Filters

Combine multiple conditions for sophisticated filtering:

```bash
# Suspicious SSH traffic from external sources
net dump -read TCP.ncap.gz -filter "DstPort == 22 && IsPublicIP(SrcIP) && SYN"

# Large DNS responses (possible exfiltration)
net dump -read DNS.ncap.gz -filter "len(Answers) > 10"

# HTTP requests to IP addresses (not domains)
net dump -read HTTP.ncap.gz -filter "MatchesPattern(Host, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$')"
```

## Performance Considerations

### Filter Compilation

Filters are compiled once before processing records. The compilation validates the expression syntax and checks that field names are valid for the audit record type.

### Evaluation Performance

- **Simple comparisons** (equality, numeric) are very fast
- **String operations** (contains, regex) are moderately fast
- **Complex expressions** with many conditions may impact throughput

### Optimization Tips

1. **Place simple conditions first** in AND expressions:
   ```bash
   DstPort == 443 && MatchesPattern(URL, "complex.*regex")
   ```

2. **Use specific field checks** instead of regex when possible:
   ```bash
   # Prefer this:
   Method == "POST"
   
   # Over this:
   MatchesPattern(Method, "POST")
   ```

3. **Limit regex complexity** - simple patterns are faster than complex ones

4. **Use helper functions** - they're optimized native Go code:
   ```bash
   # Prefer this:
   IsPrivateIP(SrcIP)
   
   # Over this:
   InSubnet(SrcIP, "10.0.0.0/8") || InSubnet(SrcIP, "172.16.0.0/12") || InSubnet(SrcIP, "192.168.0.0/16")
   ```

### Benchmarks

On typical hardware processing a 1GB audit record file:

- **No filter**: ~500,000 records/sec
- **Simple filter** (port equality): ~480,000 records/sec (4% overhead)
- **Complex filter** (regex + multiple conditions): ~350,000 records/sec (30% overhead)

## Error Handling

### Compilation Errors

If a filter expression has syntax errors or references invalid fields, an error is reported before processing begins:

```bash
$ net dump -read TCP.ncap.gz -filter "InvalidField == 123"
Error: failed to compile filter expression: undefined identifier "InvalidField"
```

### Runtime Errors

If a filter evaluation fails (rare), a warning is logged and the record is skipped:

```bash
warning: filter evaluation error: type mismatch
```

## Next Steps

- See [RULES_ENGINE.md](RULES_ENGINE.md) for information on creating alerting rules
- Check [examples/filters/](examples/filters/) for more filter examples
- Read the [expr-lang documentation](https://expr-lang.org/docs/language-definition) for complete expression syntax

