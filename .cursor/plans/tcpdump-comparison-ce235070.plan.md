<!-- ce235070-e363-48ac-996a-90b3a7d00681 0b4e64cc-b06e-4bcb-be1f-4d1ee0c85e90 -->
# tcpdump vs netcap Protocol Field Comparison Test Suite

## Overview

Build a test framework that processes pcaps through both tcpdump -A and netcap, then compares the extracted protocol fields to ensure netcap correctly parses application-layer data.

## Approach

### 1. Test Infrastructure

Create a new test file at `tests/integration/tcpdump_comparison_test.go` with:

- A helper function to run `tcpdump -A -r <pcap>` and capture ASCII payload output
- A helper function to run netcap capture and read the resulting audit records (HTTP, DNS, etc.)
- Protocol-specific parsers to extract fields from tcpdump ASCII output (e.g., parse HTTP headers from raw text)

### 2. Protocol Comparisons

For each supported protocol, compare key fields:

| Protocol | tcpdump -A extraction | netcap fields |

|----------|----------------------|---------------|

| HTTP | Parse `GET/POST`, `Host:`, `User-Agent:` from ASCII | `HTTP.Method`, `HTTP.Host`, `HTTP.UserAgent` |

| DNS | Parse query names from ASCII payload | `DNS.Questions[].Name` |

| DHCP | Parse transaction ID, options | `DHCPv4.TransactionID` |

### 3. Test Structure

```go
func TestTcpdumpComparison_HTTP(t *testing.T) {
    pcap := "../pcaps/layer7/http_espn.pcap"
    
    // Get tcpdump ASCII output
    tcpdumpData := runTcpdump(t, pcap)
    httpFields := parseTcpdumpHTTP(tcpdumpData)
    
    // Get netcap HTTP records
    netcapHTTP := runNetcapAndReadHTTP(t, pcap)
    
    // Compare fields
    for _, req := range httpFields {
        found := findMatchingNetcapRecord(netcapHTTP, req)
        assert.NotNil(t, found)
        assert.Equal(t, req.Host, found.Host)
    }
}
```

### 4. Test PCaps from tests/pcaps/

| Layer | Files | Protocols to Test |

|-------|-------|-------------------|

| layer7 | `http_espn.pcap`, `http_google.pcap` | HTTP method, host, user-agent |

| layer7 | `dns_query_response.pcap`, `dns.pcap` | DNS query names, response codes |

| layer7 | `dhcp_*.pcap` | DHCP transaction IDs |

| layer4 | `tcp_handshake.pcap` | TCP flags, ports (basic validation) |

## Key Files to Create/Modify

- **Create**: [`tests/integration/tcpdump_comparison_test.go`](tests/integration/tcpdump_comparison_test.go) - Main test file
- **Create**: [`tests/integration/tcpdump_helpers.go`](tests/integration/tcpdump_helpers.go) - Helper functions for running tcpdump and parsing output
- **Reference**: [`collector/collector.go`](collector/collector.go) - For netcap capture patterns
- **Reference**: [`io/netcap.go`](io/netcap.go) - For reading .ncap.gz files

## Implementation Notes

1. Tests require `tcpdump` to be installed (skip test if not available)
2. Use `t.TempDir()` for netcap output to avoid test pollution
3. Add `//go:build integration` tag to run separately from unit tests
4. Focus on field presence and approximate matching (timestamps may vary slightly)

### To-dos

- [ ] Create tcpdump_helpers.go with runTcpdump() and ASCII payload parsers
- [ ] Create tcpdump_comparison_test.go with HTTP, DNS, and DHCP comparison tests
- [ ] Run tests against tests/pcaps/ to verify correctness