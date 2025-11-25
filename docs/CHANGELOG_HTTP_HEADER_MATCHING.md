# HTTP Header Service Matching Feature

## Summary

Enhanced the service probe matching system to extract technology information from HTTP response headers when nmap service probes don't deliver results.

## Changes Made

### 1. Modified Files

#### `decoder/stream/service/service_probe.go`
- Added `bufio` and `net/http` imports for HTTP response parsing
- Added `matchHTTPHeaders()` function to parse HTTP responses and extract header information
- Added `parseHeaderValue()` function to dispatch header parsing based on header name
- Added header-specific parsers:
  - `parseServerHeader()` - Parses Server headers (e.g., "Apache/2.4.41")
  - `parseXPoweredByHeader()` - Parses X-Powered-By headers (e.g., "PHP/7.4.3")
  - `parseGeneratorHeader()` - Parses X-Generator headers (e.g., "WordPress 5.8")
  - `parseViaHeader()` - Parses Via headers (e.g., "1.1 varnish")
- Integrated HTTP header matching into `MatchServiceProbes()` as a fallback when no probe matches are found

### 2. New Files

#### `decoder/stream/service/http_header_test.go`
- Comprehensive test suite for all HTTP header parsing functions
- Tests for `parseServerHeader()` with various formats (Apache, nginx, IIS, cloudflare)
- Tests for `parseXPoweredByHeader()` (PHP, ASP.NET, Express)
- Tests for `parseGeneratorHeader()` (WordPress, Drupal, Jekyll)
- Tests for `parseViaHeader()` (Varnish, Squid, invalid formats)
- Integration tests for `matchHTTPHeaders()` with full HTTP responses
- Edge case tests for invalid/non-HTTP banners

#### `decoder/stream/service/HTTP_HEADER_MATCHING.md`
- Comprehensive documentation of the new feature
- Usage examples with real-world header formats
- Implementation details and function descriptions
- Testing instructions
- Future enhancement suggestions

## Feature Details

### Priority Headers (in order)
1. **Server** - Primary service identification
2. **X-Powered-By** - Framework/language detection
3. **X-AspNet-Version** - ASP.NET version
4. **X-AspNetMvc-Version** - ASP.NET MVC version
5. **X-Generator** - CMS identification
6. **Via** - Proxy detection
7. **X-Cache** - CDN detection

### Behavior
- Only activates when nmap service probes find no matches
- Checks if banner is a valid HTTP response
- Extracts the first matching header from the priority list
- Parses header value to extract product, version, and vendor
- Updates Service record fields: Product, Version, Vendor, MatchedProbeID
- Generates Software audit record for tracking

### Data Stored

**Service Record:**
- `Product`: Identified software (e.g., "nginx", "Apache", "WordPress")
- `Version`: Software version if present (e.g., "1.18.0", "2.4.41")
- `Vendor`: Vendor information if derivable
- `MatchedProbeID`: Set to "http-header-<headername>" (e.g., "http-header-server")

**Software Audit Record:**
- Full software details with source attribution
- SourceName: "HTTP Header Match: <HeaderName>"
- Notes: Complete header name and value

## Testing

All tests pass successfully:
```bash
$ cd decoder/stream/service && go test -v
=== RUN   TestParseServerHeader
--- PASS: TestParseServerHeader (0.00s)
=== RUN   TestParseXPoweredByHeader
--- PASS: TestParseXPoweredByHeader (0.00s)
=== RUN   TestParseGeneratorHeader
--- PASS: TestParseGeneratorHeader (0.00s)
=== RUN   TestParseViaHeader
--- PASS: TestParseViaHeader (0.00s)
=== RUN   TestMatchHTTPHeaders
--- PASS: TestMatchHTTPHeaders (0.00s)
=== RUN   TestMatchHTTPHeadersInvalidBanner
--- PASS: TestMatchHTTPHeadersInvalidBanner (0.00s)
PASS
ok      github.com/dreadl0ck/netcap/decoder/stream/service    10.742s
```

## Benefits

1. **Enhanced Service Detection**: Identifies web services that don't match standard nmap probes
2. **Technology Stack Visibility**: Reveals frameworks, CMS platforms, proxies, and CDNs
3. **Version Intelligence**: Extracts precise version numbers when available
4. **Non-Breaking**: Only activates as fallback, doesn't affect existing probe matching
5. **Comprehensive Coverage**: Supports common web technologies (Apache, nginx, PHP, WordPress, etc.)

## Examples

### Before (nmap probes fail)
```
Service: port=80 protocol=TCP name=http
Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0..."
Product: (empty)
Version: (empty)
```

### After (HTTP header matching)
```
Service: port=80 protocol=TCP name=http
Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0..."
Product: nginx
Version: 1.18.0
MatchedProbeID: http-header-server
```

## Compatibility

- Backward compatible with existing service probe matching
- No configuration changes required
- Works with both TCP and UDP protocols
- Integrates seamlessly with existing Software audit records

## Performance Impact

- Minimal overhead (only processes HTTP responses when probes fail)
- Fast HTTP parsing using Go's standard `net/http` library
- Single-pass header extraction
- Early exit when first priority header is found

