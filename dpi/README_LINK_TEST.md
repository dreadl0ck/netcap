# DPI Decoder Source Link Validation

## Overview

The `source_links_test.go` file contains automated tests to verify that all DPI (Deep Packet Inspection) decoder source code links are accessible on GitHub. The test intelligently handles different implementation methods used by DPI libraries.

## What It Tests

The test validates links to source code for over **1000+ protocol decoders** across three DPI modules:

1. **nDPI** (~467 protocols)
   - C source files: `https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/*.c`
   - IP lists: `https://github.com/ntop/nDPI/tree/dev/lists/protocols` (for cloud services, CDNs)
   - Content match: `https://github.com/ntop/nDPI/blob/dev/src/lib/ndpi_content_match.c.inc` (hardcoded IPs/domains)
   - Protocol IDs: `https://github.com/ntop/nDPI/blob/dev/src/include/ndpi_protocol_ids.h` (fallback)

2. **Libprotoident** (~527 protocols)
   - TCP protocols: `https://github.com/LibtraceTeam/libprotoident/blob/master/lib/tcp/lpi_*.cc`
   - UDP protocols: `https://github.com/LibtraceTeam/libprotoident/blob/master/lib/udp/lpi_*.cc`
   - Wiki: `https://github.com/LibtraceTeam/libprotoident/wiki/SupportedProtocols` (fallback)

3. **go-dpi** (~13 protocols)
   - Go classifiers: `https://github.com/dreadl0ck/go-dpi/blob/master/modules/classifiers/*.go`

## Running the Tests

### Check All Source Links
```bash
go test -v -run TestDecoderSourceLinks ./dpi/
```

**Note:** This test checks 1000+ URLs and may take several minutes. GitHub rate limiting (503/429 errors) is expected when checking many URLs rapidly.

### Quick Validation Tests
```bash
# Test URL generation logic
go test -v -run TestProtocolSourceURLGeneration ./dpi/

# Test multi-URL resolution (fallback URLs)
go test -v -run TestMultiURLResolution ./dpi/

# Test module availability
go test -v -run TestModuleProtocolsAvailable ./dpi/
```

### Run All Tests
```bash
go test -v ./dpi/
```

## Test Behavior

- **Does NOT fail the build** - The test reports broken links but doesn't cause test failure
- **Handles rate limiting** - Distinguishes between actual broken links (404) and rate limiting (503/429)
- **Deduplicates URLs** - Only checks each unique URL once
- **Multi-URL resolution** - Tries multiple fallback URLs per protocol when primary link fails
- **Provides detailed reporting** - Logs all broken links with HTTP status codes
- **Smart fallbacks** - For protocols detected via IP lists or SNI/host headers, links to appropriate documentation

## Output

The test provides:
- Total number of links checked
- Number of successfully verified links
- List of broken links (404, etc.)
- List of rate-limited URLs (if any)

## Why This Matters

The frontend DPI page (`cmd/capture/webui/frontend/src/pages/dpi.tsx`) displays links to decoder source code for each protocol. This test ensures those links are valid and help users:

- Understand how each protocol is detected
- Review the detection logic
- Contribute to the upstream projects
- Find documentation for protocols detected via IP lists or SNI/host headers

## Implementation Details

### Different Detection Methods

nDPI uses several methods to detect protocols:

1. **C Source Files** - Traditional packet inspection (e.g., `tls.c`, `http.c`)
2. **IP Lists** - Cloud services detected by IP ranges (e.g., [`266_salesforce.list`](https://github.com/ntop/nDPI/blob/dev/lists/protocols/266_salesforce.list))
3. **Content Match** - Hardcoded IPs and domain names in [`ndpi_content_match.c.inc`](https://github.com/ntop/nDPI/blob/dev/src/lib/ndpi_content_match.c.inc)
   - IP-based: OCS (Orange Cinéma Séries), TeamViewer
   - Domain-based: Advertising/tracking networks (pubmatic.com, openx.com, etc.)
4. **SNI/Host Detection** - TLS SNI or HTTP Host headers (e.g., Facebook, Netflix)
5. **Protocol Aliases** - Some protocols are subsets of others

The test intelligently determines which method is likely used based on the protocol name and provides appropriate fallback URLs.

### Frontend Integration

The TypeScript frontend (`cmd/capture/webui/frontend/src/pages/dpi.tsx`) has been updated to match the backend logic:

- `isLikelyIPListProtocol()` - Identifies protocols using IP list detection
- `isLikelyContentMatchProtocol()` - Identifies protocols using hardcoded IPs/domains
- `getProtocolSourceUrl()` - Returns appropriate URLs based on detection method
- UDP protocols (libprotoident) correctly link to `lib/udp/` directory

**Detection Priority (nDPI):**
1. Content match protocols → `ndpi_content_match.c.inc`
2. IP list protocols → `lists/protocols/` directory
3. Standard protocols → `protocols/*.c` files

## Example Issues Found

During development, the test identified:
- 404 errors for protocols that were renamed or moved
- Missing protocol implementations
- Incorrect URL patterns

## Maintenance

When adding new protocols or updating DPI libraries:
1. Run this test to verify new links
2. Update URL generation logic in `getProtocolSourceURL()` if needed
3. Check the test output for any broken links

