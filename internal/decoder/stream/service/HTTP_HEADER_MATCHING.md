# HTTP Header Service Matching

## Overview

When nmap service probes don't deliver results or don't extract product information, the service detection system falls back to checking HTTP response headers for known technology indicators. This provides an additional layer of service identification for HTTP/HTTPS services.

## How It Works

1. **Primary Detection**: The system first attempts to match the service banner against all nmap service probes
2. **Fallback to HTTP Headers**: If no probe matches are found **OR** if a probe matched but the Product field is still empty, the system checks if the banner is a valid HTTP response
3. **Header Extraction**: If valid HTTP, the system checks specific headers in priority order
4. **Information Parsing**: The first matching header is parsed to extract product, version, and vendor information
5. **Result Storage**: The extracted information is stored in the Service record and also written as a Software detection

## Trigger Conditions

HTTP header matching is triggered when:
- No nmap service probe matched the banner, **OR**
- A service probe matched but did not populate the Product field

This ensures that valuable information in HTTP headers (like `Server: gws`) is always extracted, even when generic HTTP probes match without extracting specific product details.

## Priority Headers

Headers are checked in the following priority order (stops at first match):

1. **Server** - Primary service identification (e.g., `nginx/1.18.0`, `Apache/2.4.41`)
2. **X-Powered-By** - Framework/language detection (e.g., `PHP/7.4.3`, `ASP.NET`)
3. **X-AspNet-Version** - ASP.NET application version
4. **X-AspNetMvc-Version** - ASP.NET MVC application version
5. **X-Generator** - CMS identification (e.g., `WordPress 5.8`, `Drupal 9`)
6. **Via** - Proxy detection (e.g., `1.1 varnish`, `1.1 squid/4.10`)
7. **X-Cache** - CDN detection (e.g., `HIT from cloudflare`)

## Parsing Examples

### Server Header
```
Server: Apache/2.4.41 (Ubuntu)
→ Product: Apache
→ Version: 2.4.41

Server: nginx/1.18.0
→ Product: nginx
→ Version: 1.18.0

Server: Microsoft-IIS/10.0
→ Product: Microsoft-IIS
→ Version: 10.0

Server: gws
→ Product: gws
→ Version: (empty)
```

### X-Powered-By Header
```
X-Powered-By: PHP/7.4.3
→ Product: PHP
→ Version: 7.4.3

X-Powered-By: ASP.NET
→ Product: ASP.NET
→ Version: (empty)
```

### X-Generator Header
```
X-Generator: WordPress 5.8
→ Product: WordPress
→ Version: 5.8

X-Generator: Jekyll v4.2.0
→ Product: Jekyll
→ Version: 4.2.0
```

### Via Header
```
Via: 1.1 varnish
→ Product: varnish
→ Version: (empty)

Via: 1.1 squid/4.10
→ Product: squid
→ Version: 4.10
```

## Service Record Updates

When a match is found, the following fields are updated in the Service record:

- **Product**: The identified software product name
- **Version**: The software version (if available)
- **Vendor**: The software vendor (if available)
- **MatchedProbeID**: Set to `http-header-<headername>` (e.g., `http-header-server`)

## Software Record Generation

A Software audit record is also generated with:
- **Product**: Identified product
- **Version**: Identified version
- **Vendor**: Identified vendor
- **SourceName**: `HTTP Header Match: <HeaderName>`
- **Service**: The service name from port lookup
- **Flows**: Associated network flow identifiers
- **Notes**: Full header name and value for reference

## Implementation Details

### Function: `matchHTTPHeaders`

Located in `decoder/stream/service/service_probe.go`, this function:
1. Attempts to parse the banner as an HTTP response
2. Checks headers in priority order
3. Calls `parseHeaderValue` to extract information
4. Logs the match result

### Helper Functions

- **parseServerHeader**: Parses `Server` header format
- **parseXPoweredByHeader**: Parses `X-Powered-By` header format
- **parseGeneratorHeader**: Parses `X-Generator` header format
- **parseViaHeader**: Parses `Via` header format

## Benefits

1. **Enhanced Detection**: Catches services that don't match nmap probes or where probes don't extract product information
2. **Technology Stack Visibility**: Reveals web frameworks, CMS platforms, and proxy layers
3. **Version Intelligence**: Extracts version information when available
4. **Smart Fallback**: Activates when primary detection fails or is incomplete
5. **Priority-Based**: Uses the most reliable headers first
6. **Complementary Detection**: Works alongside nmap probes to maximize information extraction

## Testing

Comprehensive tests are available in `http_header_test.go`:
- Individual header parser tests
- Integration tests with full HTTP responses
- Edge case handling (invalid banners, missing headers)

Run tests:
```bash
cd decoder/stream/service
go test -v -run "TestParse|TestMatchHTTP"
```

## Logging

HTTP header matches are logged at DEBUG level:
```
HTTP header match: ident=<flow-id> header=<header-name> value=<header-value> product=<product> version=<version>
```

## Example Scenario

Consider this HTTP response banner:
```
HTTP/1.1 200 OK
Date: Wed, 15 Nov 2017 15:09:45 GMT
Expires: -1
Cache-Control: private, max-age=0
Content-Type: text/html; charset=ISO-8859-1
P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
Server: gws
X-XSS-Protection: 1; mode=b
```

**Before the fix**: If a generic HTTP probe matched this banner but didn't extract the `Server` header value, the Product field would remain empty even though `Server: gws` is present.

**After the fix**: The HTTP header matching logic checks if the Product field is empty after probe matching. Since it's empty, it extracts the `Server: gws` header and populates:
- Product: `gws`
- MatchedProbeID: `http-header-server`

This ensures that HTTP header information is never lost, even when service probes provide incomplete matches.

## Future Enhancements

Potential improvements for future versions:
- Support for additional headers (e.g., `X-AspNet-WebPages-Version`, `X-Runtime`)
- Multiple header aggregation (combine information from multiple headers)
- Header-based vendor inference (e.g., "Apache" → "Apache Software Foundation")
- Technology stack correlation (detect common technology combinations)

