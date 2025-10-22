# Netcap Comprehensive Test Suite and Regression Test Plan

**Version:** 1.0  
**Date:** October 21, 2025  
**Status:** Draft  

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current State Analysis](#current-state-analysis)
3. [Test Strategy](#test-strategy)
4. [Test Infrastructure](#test-infrastructure)
5. [Unit Tests](#unit-tests)
6. [Integration Tests](#integration-tests)
7. [Regression Tests](#regression-tests)
8. [Performance Tests](#performance-tests)
9. [E2E Tests](#e2e-tests)
10. [Test Data Management](#test-data-management)
11. [CI/CD Integration](#cicd-integration)
12. [Implementation Roadmap](#implementation-roadmap)
13. [Success Metrics](#success-metrics)

---

## Executive Summary

This document outlines a comprehensive testing strategy for the Netcap framework. Netcap is a complex network analysis system with 58+ protocol decoders, 9 CLI tools, stream reassembly, and multiple output formats. The current test coverage is insufficient with many critical components untested.

### Key Objectives

1. Achieve **80%+ code coverage** across all packages
2. Establish **regression test suite** with golden file comparisons
3. Create **performance benchmarks** for critical paths
4. Implement **continuous testing** in CI/CD pipeline
5. Provide **test fixtures** and **mock data** for deterministic testing

---

## Current State Analysis

### Test Coverage Status

Based on `go test -cover ./...` output:

| Package | Current Coverage | Test Files | Status |
|---------|------------------|------------|--------|
| **Core Packages** |
| collector | Build failed | ✓ collector_test.go, pcap_test.go | ❌ Needs fix |
| decoder/packet | Build failed | ✓ packet_decoder_test.go, utils_test.go | ❌ Needs fix |
| decoder/stream | 0% | Few tests | ⚠️ Critical gap |
| reassembly | 68.9% | ✓ tcpassembly_test.go | ⚠️ 4 failing tests |
| types | 0.8% | ✓ utils_test.go, netcap.pb_test.go | ❌ Critical gap |
| **I/O & Storage** |
| io | 19.7% | ✓ Multiple test files | ⚠️ Low coverage |
| encoder | 64.0% | ✓ encoder_test.go | ✓ Good |
| delimited | 69.0% | ✓ delimited_test.go | ✓ Good |
| **Utilities** |
| logger | 89.5% | ✓ log_test.go | ✓ Excellent |
| utils | 29.3% | ✓ Multiple test files | ⚠️ Low coverage |
| resolvers | Build failed | ✓ Multiple test files | ❌ Missing data files |
| **Stream Decoders** |
| decoder/stream/credentials | 52.8% | ✓ credentials_test.go | ✓ Good |
| decoder/stream/exploit | 0% | ✓ exploit_test.go (failing) | ❌ Index missing |
| decoder/stream/service | 24.8% | ✓ service_probe_test.go (failing) | ⚠️ Index missing |
| decoder/stream/software | 2.1% | ✓ software_test.go | ❌ Low coverage |
| decoder/stream/ssh | 2.3% | ✓ ssh_reader_test.go | ❌ Low coverage |
| decoder/stream/vulnerability | 0% | ✓ vulnerability_test.go (failing) | ❌ Index missing |
| **Label & Analysis** |
| label/manager | 49.3% | ✓ manager_test.go, scatter_test.go | ⚠️ Medium coverage |
| analyze | 0% | ❌ No tests | ❌ Critical gap |
| **Commands (All 0% or build failed)** |
| cmd/* | 0% | ❌ No tests for any command | ❌ Critical gap |
| **Maltego** |
| maltego | Build failed | ✓ 4 test files | ❌ Needs fix |
| **DPI & DBS** |
| dpi | Build failed | ❌ No tests | ❌ nDPI dependency issue |
| dbs | Build failed | ✓ index_test.go | ❌ Unused variables |

### Critical Issues Identified

1. **Build Failures**
   - DPI package: Missing nDPI library headers
   - DBS package: Unused variables in server.go
   - Multiple packages fail to compile for tests

2. **Missing Test Data**
   - Bleve indices required for exploit, service, vulnerability tests
   - DHCP fingerprints CSV missing for resolvers
   - No standardized test PCAP fixtures

3. **Failing Tests**
   - 4 reassembly tests failing (KeepSimple boundary issues)
   - Index-dependent tests failing (exploit, service, vulnerability)
   - IPv6 numeric representation test intentionally failing (TODO)

4. **No Test Coverage**
   - **66 packet decoder files** - mostly untested
   - **63+ stream decoder files** - mostly untested
   - **All 9 CLI commands** - completely untested
   - Analysis package - no tests
   - Alert package - no tests

---

## Test Strategy

### Testing Pyramid

```
                    ┌─────────────┐
                    │   E2E (5%)  │ Full CLI workflows
                    ├─────────────┤
                ┌───┤ Integration │ (15%) Multi-component tests
                │   └─────────────┘
            ┌───┤
        ┌───┤   └──────┬──────────┐
        │   │          │Performance│ (10%) Benchmarks & profiling
    ┌───┤   │          └──────────┘
    │   │   └─────────────────────┐
    │   └────┬                    │ Regression (15%) Golden file tests
    │        │    ┌───────────────┤
    └────────┤    │               │
             │    │   Unit Tests  │ (55%) Component isolation
             └────┴───────────────┘
```

### Test Categories

#### 1. Unit Tests (55% of effort)
- Individual function/method testing
- Mock external dependencies
- Fast execution (< 5s total)
- No network or file I/O where possible

#### 2. Integration Tests (15% of effort)
- Multi-component interactions
- Real file I/O with test fixtures
- Database interactions
- Stream reassembly with test PCAPs

#### 3. Regression Tests (15% of effort)
- Golden file comparisons
- Known-good PCAP processing
- Output validation against baselines
- Protocol decoder correctness

#### 4. Performance Tests (10% of effort)
- Benchmarks for critical paths
- Memory profiling
- Throughput measurements
- Scalability tests

#### 5. E2E Tests (5% of effort)
- Full CLI command workflows
- Live capture simulation
- Multi-tool integration
- Error handling scenarios

---

## Test Infrastructure

### Directory Structure

```
netcap/
├── tests/
│   ├── fixtures/
│   │   ├── pcaps/              # Test PCAP files
│   │   │   ├── http/
│   │   │   ├── tls/
│   │   │   ├── dns/
│   │   │   ├── malformed/      # Edge cases
│   │   │   └── protocols/      # One per protocol
│   │   ├── golden/             # Expected outputs
│   │   │   ├── csv/
│   │   │   ├── json/
│   │   │   └── proto/
│   │   ├── configs/            # Test configurations
│   │   └── databases/          # Test DB files
│   ├── integration/            # Integration test suites
│   │   ├── collector_test.go
│   │   ├── decoder_test.go
│   │   └── pipeline_test.go
│   ├── regression/             # Regression test suites
│   │   ├── decoder_regression_test.go
│   │   └── cli_regression_test.go
│   ├── e2e/                    # End-to-end tests
│   │   ├── capture_test.go
│   │   └── transform_test.go
│   ├── benchmarks/             # Performance tests
│   │   ├── collector_bench_test.go
│   │   └── decoder_bench_test.go
│   ├── helpers/                # Test utilities
│   │   ├── pcap_generator.go
│   │   ├── comparators.go
│   │   └── fixtures.go
│   └── testdata/               # Existing test data (keep)
└── pkg_test.go files           # Co-located with source
```

### Test Utilities Library

Create `helpers/` with reusable components:

```go
// helpers/fixtures.go
type TestFixture struct {
    PcapPath     string
    ExpectedType types.Type
    PacketCount  int
    Golden       GoldenFiles
}

func LoadFixture(name string) (*TestFixture, error)
func CompareAuditRecords(got, want proto.Message) error
func GenerateTestPCAP(config PcapConfig) (string, error)
```

### Mock Objects

Create mocks for:
- File writers (testing without disk I/O)
- Network interfaces (live capture testing)
- External resolvers (DNS, GeoIP, etc.)
- Database connections

### Golden File Management

```bash
# Generate new golden files
make test-golden-generate

# Update golden files after intentional changes
make test-golden-update

# Compare against golden files
make test-golden-verify
```

---

## Unit Tests

### 5.1 Collector Package

**Priority: Critical**

#### Test Coverage Goals: 85%+

**Test Files to Create/Enhance:**
- `collector/collector_test.go` (enhance existing)
- `collector/worker_test.go` (new)
- `collector/pcap_test.go` (enhance existing)
- `collector/live_test.go` (new)
- `collector/batch_test.go` (new)
- `collector/utils_test.go` (new)

**Test Cases:**

```go
// collector/collector_test.go
func TestCollector_New(t *testing.T)
func TestCollector_Init(t *testing.T)
func TestCollector_InitWithInvalidConfig(t *testing.T)
func TestCollector_InitDecoders(t *testing.T)
func TestCollector_SignalHandling(t *testing.T)

// collector/worker_test.go
func TestWorkerPool_Creation(t *testing.T)
func TestWorkerPool_PacketDistribution(t *testing.T)
func TestWorkerPool_Cleanup(t *testing.T)
func TestWorkerPool_ConcurrentSafety(t *testing.T)

// collector/pcap_test.go (enhance)
func TestCollectPcap_ValidFile(t *testing.T)
func TestCollectPcap_MalformedFile(t *testing.T)
func TestCollectPcap_EmptyFile(t *testing.T)
func TestCollectPcap_LargeFile(t *testing.T)
func TestCollectPcapNG_ValidFile(t *testing.T)
func TestCountPackets(t *testing.T)

// collector/live_test.go (new)
func TestCollectLive_Interface(t *testing.T)
func TestCollectLive_WithBPF(t *testing.T)
func TestCollectLive_ContextCancellation(t *testing.T)
func TestCollectLive_InvalidInterface(t *testing.T)

// collector/batch_test.go (new)
func TestInitBatching(t *testing.T)
func TestBatchInfo_Channels(t *testing.T)

// collector/utils_test.go (new)
func TestHandleLinkType(t *testing.T)
func TestCreateOutputFiles(t *testing.T)
func TestProgressReporting(t *testing.T)
```

**Mock Strategy:**
- Mock file system for output tests
- Mock pcap.Handle for live capture tests
- Use small, deterministic test PCAPs

---

### 5.2 Decoder Packages

**Priority: Critical**

#### Packet Decoders (decoder/packet/)

**Test Coverage Goal: 75%+ for each decoder**

**66 Protocol Decoders to Test:**

Create comprehensive test file for each protocol decoder:

```go
// decoder/packet/eth_test.go
func TestEthernetDecoder_New(t *testing.T)
func TestEthernetDecoder_Decode(t *testing.T)
func TestEthernetDecoder_CSVOutput(t *testing.T)
func TestEthernetDecoder_InvalidPacket(t *testing.T)
func TestEthernetDecoder_EdgeCases(t *testing.T)
func BenchmarkEthernetDecoder_Decode(b *testing.B)

// Similar for all 66 decoders:
// arp, bfd, cip, dhcp4, dhcp6, dns, dot11, dot1q, eap, eapol, etc.
```

**Test Template for Each Decoder:**

```go
// Template: decoder/packet/PROTOCOL_test.go
package packet_test

import (
    "testing"
    "github.com/dreadl0ck/netcap/decoder/packet"
    "github.com/dreadl0ck/netcap/helpers"
)

func TestPROTOCOL_Decode(t *testing.T) {
    tests := []struct{
        name        string
        pcapFile    string
        wantRecords int
        wantErr     bool
    }{
        {"valid packet", "fixtures/PROTOCOL_valid.pcap", 1, false},
        {"malformed", "fixtures/PROTOCOL_malformed.pcap", 0, false},
        {"empty", "fixtures/PROTOCOL_empty.pcap", 0, false},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}

func TestPROTOCOL_CSVOutput(t *testing.T) { /* ... */ }
func TestPROTOCOL_JSONOutput(t *testing.T) { /* ... */ }
func BenchmarkPROTOCOL_Decode(b *testing.B) { /* ... */ }
```

**Priority Decoders** (most critical protocols):
1. **Tier 1** (Immediate): ethernet, ipv4, ipv6, tcp, udp, dns, http
2. **Tier 2** (High): tls_client_hello, tls_server_hello, dhcp4, dhcp6, arp
3. **Tier 3** (Medium): icmp4, icmp6, dot1q, connection, device_profile, ip_profile
4. **Tier 4** (Lower): Industrial protocols (modbus, cip, enip), specialized protocols

#### Stream Decoders (decoder/stream/)

**Test Coverage Goal: 70%+**

**Test Files to Create/Enhance:**

```go
// decoder/stream/http/http_test.go (new)
func TestHTTPDecoder_ParseRequest(t *testing.T)
func TestHTTPDecoder_ParseResponse(t *testing.T)
func TestHTTPDecoder_MultipleRequests(t *testing.T)
func TestHTTPDecoder_ChunkedEncoding(t *testing.T)
func TestHTTPDecoder_Compression(t *testing.T)
func TestHTTPDecoder_Malformed(t *testing.T)

// decoder/stream/smtp/smtp_test.go (enhance)
func TestSMTPDecoder_Commands(t *testing.T)
func TestSMTPDecoder_EmailParsing(t *testing.T)
func TestSMTPDecoder_Attachments(t *testing.T)

// decoder/stream/ssh/ssh_test.go (enhance)
func TestSSHDecoder_Handshake(t *testing.T)
func TestSSHDecoder_KeyExchange(t *testing.T)
func TestSSHDecoder_VersionNegotiation(t *testing.T)

// decoder/stream/credentials/credentials_test.go (enhance existing 52.8%)
func TestCredentialExtraction_HTTP(t *testing.T)
func TestCredentialExtraction_FTP(t *testing.T)
func TestCredentialExtraction_Telnet(t *testing.T)
func TestCredentialExtraction_IMAP(t *testing.T)

// decoder/stream/file/file_test.go (new)
func TestFileExtraction_HTTP(t *testing.T)
func TestFileExtraction_FTP(t *testing.T)
func TestFileExtraction_SMTP(t *testing.T)
func TestFileExtraction_ContentTypes(t *testing.T)

// decoder/stream/service/service_test.go (enhance, fix index issue)
func TestServiceProbe_Matching(t *testing.T)
func TestServiceProbe_BannerGrabbing(t *testing.T)
func TestServiceProbe_CPEExtraction(t *testing.T)
func TestServiceProbe_WithoutIndex(t *testing.T)  // Fallback mode

// decoder/stream/software/software_test.go (enhance from 2.1%)
func TestSoftwareDetection_Headers(t *testing.T)
func TestSoftwareDetection_Cookies(t *testing.T)
func TestSoftwareDetection_MetaTags(t *testing.T)
func TestSoftwareDetection_JavaScript(t *testing.T)

// decoder/stream/vulnerability/vulnerability_test.go (fix, enhance)
func TestVulnerabilityLookup_CPE(t *testing.T)
func TestVulnerabilityLookup_NVD(t *testing.T)
func TestVulnerabilityLookup_Caching(t *testing.T)
func TestVulnerabilityLookup_Offline(t *testing.T)  // Without index

// decoder/stream/exploit/exploit_test.go (fix, enhance)
func TestExploitDetection_Patterns(t *testing.T)
func TestExploitDetection_Signatures(t *testing.T)
func TestExploitDetection_SQLInjection(t *testing.T)
func TestExploitDetection_XSS(t *testing.T)
func TestExploitDetection_Offline(t *testing.T)  // Without index

// decoder/stream/mail/mail_test.go (new)
func TestMailParsing_Headers(t *testing.T)
func TestMailParsing_Multipart(t *testing.T)
func TestMailParsing_Attachments(t *testing.T)
```

**Stream Decoder Test Priorities:**
1. **HTTP** - Most common protocol
2. **TLS** - Security critical
3. **SSH** - Authentication & security
4. **Credentials** - Already partially tested (52.8%)
5. **Service/Software Detection** - Fix index dependencies
6. **File Extraction** - Important for forensics
7. **Mail (SMTP/POP3)** - Communication analysis

---

### 5.3 Types Package

**Priority: Critical**

**Current: 0.8% → Target: 80%+**

**Test Files to Create:**

```go
// types/audit_record_test.go (new)
func TestAuditRecord_Interface(t *testing.T)  // Test all 58+ types implement interface
func TestAuditRecord_CSVHeader(t *testing.T)  // All types
func TestAuditRecord_CSVRecord(t *testing.T)  // All types
func TestAuditRecord_JSON(t *testing.T)       // All types
func TestAuditRecord_Time(t *testing.T)       // All types
func TestAuditRecord_SrcDst(t *testing.T)     // All types

// types/encoding_test.go (new)
func TestAuditRecord_ProtobufEncoding(t *testing.T)
func TestAuditRecord_ProtobufDecoding(t *testing.T)
func TestAuditRecord_RoundTrip(t *testing.T)

// types/validation_test.go (new)
func TestAuditRecord_FieldValidation(t *testing.T)
func TestAuditRecord_BoundaryCases(t *testing.T)
func TestAuditRecord_NilHandling(t *testing.T)

// Specific protocol tests (one per major type)
// types/tcp_test.go, types/http_test.go, types/connection_test.go, etc.
```

**Generate Tests for All 58 Types:**
- Connection, Ethernet, ARP, IPv4, IPv6, TCP, UDP, DNS, HTTP, TLS, etc.
- Test CSV serialization
- Test JSON serialization
- Test protobuf marshaling/unmarshaling
- Test timestamp handling
- Test metric increment

---

### 5.4 I/O Package

**Current: 19.7% → Target: 85%+**

**Test Files to Enhance/Create:**

```go
// io/writer_test.go (enhance existing)
func TestWriter_Protobuf(t *testing.T)
func TestWriter_CSV(t *testing.T)
func TestWriter_JSON(t *testing.T)
func TestWriter_Compression(t *testing.T)
func TestWriter_Buffering(t *testing.T)
func TestWriter_Concurrent(t *testing.T)

// io/reader_test.go (enhance existing)
func TestReader_Protobuf(t *testing.T)
func TestReader_CSV(t *testing.T)
func TestReader_JSON(t *testing.T)
func TestReader_Compression(t *testing.T)
func TestReader_LargeFiles(t *testing.T)
func TestReader_Corruption(t *testing.T)

// io/elastic_test.go (new)
func TestElasticsearch_Connection(t *testing.T)
func TestElasticsearch_BulkIndex(t *testing.T)
func TestElasticsearch_ErrorHandling(t *testing.T)
func TestElasticsearch_Retry(t *testing.T)

// io/prometheus_test.go (new)
func TestPrometheus_Metrics(t *testing.T)
func TestPrometheus_Export(t *testing.T)
```

---

### 5.5 Reassembly Package

**Current: 68.9% with 4 failing tests → Target: 90%+**

**Immediate Actions:**
1. **Fix 4 failing tests:**
   - TestKeepSimpleOnBoundary
   - TestKeepSimpleNotBoundaryLive
   - TestKeepSimpleNotBoundaryAlreadyKept
   - TestKeepLonger

**Test Files to Enhance:**

```go
// reassembly/tcpassembly_test.go (fix and enhance)
func TestTCPReassembly_InOrder(t *testing.T)
func TestTCPReassembly_OutOfOrder(t *testing.T)
func TestTCPReassembly_Retransmission(t *testing.T)
func TestTCPReassembly_Overlap(t *testing.T)
func TestTCPReassembly_FragmentBoundaries(t *testing.T)
func TestTCPReassembly_KeepBytes(t *testing.T)  // Fix existing
func TestTCPReassembly_MemoryManagement(t *testing.T)

// reassembly/connection_test.go (new)
func TestConnection_Lifecycle(t *testing.T)
func TestConnection_Timeout(t *testing.T)
func TestConnection_Flush(t *testing.T)

// reassembly/stream_test.go (new)
func TestStream_Bidirectional(t *testing.T)
func TestStream_Gaps(t *testing.T)
func TestStream_FastRetransmit(t *testing.T)
```

---

### 5.6 Resolvers Package

**Current: Build failed → Target: 75%+**

**Immediate Fix:** Resolve missing DHCP fingerprints file

**Test Files to Create/Enhance:**

```go
// resolvers/dns_test.go (new)
func TestDNS_ReverseLookup(t *testing.T)
func TestDNS_LocalLookup(t *testing.T)
func TestDNS_Caching(t *testing.T)

// resolvers/geoip_test.go (new)
func TestGeoIP_Lookup(t *testing.T)
func TestGeoIP_ASN(t *testing.T)
func TestGeoIP_City(t *testing.T)
func TestGeoIP_MissingDB(t *testing.T)

// resolvers/mac_test.go (new)
func TestMAC_Lookup(t *testing.T)
func TestMAC_Vendor(t *testing.T)

// resolvers/ja3_test.go (enhance existing)
func TestJA3_Fingerprint(t *testing.T)
func TestJA3_DatabaseLookup(t *testing.T)

// resolvers/dhcp_test.go (enhance existing)
func TestDHCP_Fingerprint(t *testing.T)
func TestDHCP_WithoutDatabase(t *testing.T)  // Graceful degradation
```

**Mock Strategy:**
- Create minimal test databases for GeoIP, MAC, JA3
- Mock DNS responses
- Provide fallback modes when DBs missing

---

### 5.7 Label Package

**Current: 49.3% → Target: 80%+**

**Test Files to Enhance:**

```go
// label/manager/manager_test.go (enhance)
func TestLabelManager_Loading(t *testing.T)
func TestLabelManager_Matching(t *testing.T)
func TestLabelManager_Bidirectional(t *testing.T)
func TestLabelManager_Performance(t *testing.T)

// label/manager/scatter_test.go (enhance)
func TestScatter_Distribution(t *testing.T)
func TestScatter_TimeWindows(t *testing.T)

// label/suricata_test.go (new)
func TestSuricata_AlertParsing(t *testing.T)
func TestSuricata_RuleMatching(t *testing.T)

// label/custom_test.go (new)
func TestCustom_LabelDefinition(t *testing.T)
func TestCustom_Validation(t *testing.T)
```

---

### 5.8 Utility Packages

#### Utils Package
**Current: 29.3% → Target: 85%+**

```go
// utils/utils_test.go (enhance)
func TestIPConversion(t *testing.T)
func TestTimestampHandling(t *testing.T)
func TestProtocolHelpers(t *testing.T)
func TestStringUtilities(t *testing.T)

// utils/ident_test.go (enhance)
func TestIdentGeneration(t *testing.T)
func TestIdentUniqueness(t *testing.T)
```

#### Logger Package
**Current: 89.5% → Target: 95%+** ✓ Already excellent

```go
// logger/log_test.go (minor enhancements)
func TestLogger_Levels(t *testing.T)
func TestLogger_Output(t *testing.T)
func TestLogger_Concurrent(t *testing.T)
```

---

## Integration Tests

**Priority: High**

### 6.1 Full Pipeline Tests

**Location:** `tests/integration/`

```go
// tests/integration/pipeline_test.go
func TestPipeline_LiveCaptureToFile(t *testing.T)
func TestPipeline_PcapToMultipleFormats(t *testing.T)
func TestPipeline_StreamReassembly(t *testing.T)
func TestPipeline_WithFiltering(t *testing.T)
func TestPipeline_LargeFile(t *testing.T)

// tests/integration/collector_decoder_test.go
func TestIntegration_CollectorWithPacketDecoders(t *testing.T)
func TestIntegration_CollectorWithStreamDecoders(t *testing.T)
func TestIntegration_CollectorWithBothDecoders(t *testing.T)
func TestIntegration_CollectorWithDPI(t *testing.T)  // If DPI available

// tests/integration/io_test.go
func TestIntegration_WriteAndRead(t *testing.T)
func TestIntegration_MultipleFormats(t *testing.T)
func TestIntegration_Compression(t *testing.T)
func TestIntegration_ElasticsearchExport(t *testing.T)

// tests/integration/resolvers_test.go
func TestIntegration_ResolversWithRealData(t *testing.T)
func TestIntegration_GeoIPEnrichment(t *testing.T)
func TestIntegration_JA3Fingerprinting(t *testing.T)
```

### 6.2 Protocol-Specific Integration Tests

```go
// tests/integration/protocols/http_test.go
func TestHTTP_FullConversation(t *testing.T)
func TestHTTP_FileExtraction(t *testing.T)
func TestHTTP_SessionReconstruction(t *testing.T)

// tests/integration/protocols/tls_test.go
func TestTLS_Handshake(t *testing.T)
func TestTLS_CertificateExtraction(t *testing.T)
func TestTLS_JA3Fingerprinting(t *testing.T)

// tests/integration/protocols/dns_test.go
func TestDNS_QueryResponse(t *testing.T)
func TestDNS_RecordTypes(t *testing.T)
func TestDNS_PassiveDNS(t *testing.T)
```

### 6.3 Multi-Component Tests

```go
// tests/integration/label_collector_test.go
func TestLabelingDuringCapture(t *testing.T)
func TestLabelingFromSuricata(t *testing.T)
func TestLabelingCustomRules(t *testing.T)

// tests/integration/export_test.go
func TestExportToPrometheus(t *testing.T)
func TestExportToElastic(t *testing.T)
func TestExportToCsv(t *testing.T)
```

---

## Regression Tests

**Priority: High**

### 7.1 Golden File Tests

**Location:** `tests/regression/`

**Strategy:** Process known PCAPs and compare outputs byte-for-byte with golden files.

```go
// tests/regression/decoder_regression_test.go
func TestRegression_AllProtocolDecoders(t *testing.T) {
    fixtures := []struct{
        name     string
        pcap     string
        golden   map[string]string  // type -> golden file path
    }{
        {
            name: "http_traffic",
            pcap: "fixtures/pcaps/http/simple_get.pcap",
            golden: map[string]string{
                "HTTP":       "fixtures/golden/http/simple_get_HTTP.csv",
                "TCP":        "fixtures/golden/http/simple_get_TCP.csv",
                "IPv4":       "fixtures/golden/http/simple_get_IPv4.csv",
                "Ethernet":   "fixtures/golden/http/simple_get_Ethernet.csv",
                "Connection": "fixtures/golden/http/simple_get_Connection.csv",
            },
        },
        // Add cases for all major protocols
    }
    
    for _, tt := range fixtures {
        t.Run(tt.name, func(t *testing.T) {
            // Run netcap capture
            // Compare outputs with golden files
            // Report differences
        })
    }
}

// tests/regression/stream_regression_test.go
func TestRegression_StreamReassembly(t *testing.T)
func TestRegression_HTTPParsing(t *testing.T)
func TestRegression_TLSParsing(t *testing.T)
func TestRegression_FileExtraction(t *testing.T)

// tests/regression/output_format_regression_test.go
func TestRegression_CSVOutput(t *testing.T)
func TestRegression_JSONOutput(t *testing.T)
func TestRegression_ProtobufOutput(t *testing.T)
```

### 7.2 Known-Good PCAP Suite

Create a comprehensive suite of test PCAPs:

**Organization:** `tests/fixtures/pcaps/`

```
pcaps/
├── protocols/              # One PCAP per protocol
│   ├── ethernet.pcap
│   ├── arp.pcap
│   ├── ipv4.pcap
│   ├── ipv6.pcap
│   ├── tcp.pcap
│   ├── udp.pcap
│   ├── icmp.pcap
│   ├── dns.pcap
│   ├── http.pcap
│   ├── https.pcap
│   ├── ssh.pcap
│   ├── smtp.pcap
│   ├── pop3.pcap
│   └── ... (58+ protocols)
├── scenarios/              # Real-world scenarios
│   ├── web_browsing.pcap
│   ├── file_download.pcap
│   ├── email_session.pcap
│   ├── video_streaming.pcap
│   └── ssh_session.pcap
├── edge_cases/             # Edge cases & malformed
│   ├── fragmented_packets.pcap
│   ├── out_of_order.pcap
│   ├── retransmissions.pcap
│   ├── malformed_headers.pcap
│   ├── truncated_packets.pcap
│   └── overlapping_segments.pcap
├── attacks/                # Security-relevant
│   ├── syn_flood.pcap
│   ├── port_scan.pcap
│   ├── sql_injection.pcap
│   ├── xss_attempt.pcap
│   └── exploit_attempts.pcap
└── industrial/             # ICS/SCADA protocols
    ├── modbus.pcap
    ├── enip.pcap
    ├── cip.pcap
    └── dnp3.pcap
```

**Sources for Test PCAPs:**
- Wireshark sample captures
- NETRESEC (pcaps.netresec.com)
- The Ultimate PCAP (already in repo: `tests/The-Ultimate-PCAP-v20200224.pcapng`)
- Malware-traffic-analysis.net
- Custom-generated synthetic traffic

### 7.3 Regression Test Automation

```bash
# Makefile targets
make test-regression          # Run all regression tests
make test-regression-update   # Update golden files
make test-regression-report   # Generate diff report
```

```go
// tests/regression/runner.go
type RegressionTest struct {
    Name            string
    InputPCAP       string
    ExpectedOutputs map[string]string  // output type -> golden file
    Config          *collector.Config
}

func (rt *RegressionTest) Run() error
func (rt *RegressionTest) Compare() ([]Diff, error)
func (rt *RegressionTest) GenerateGolden() error
```

---

## Performance Tests

**Priority: Medium**

### 8.1 Benchmarks

**Location:** `tests/benchmarks/`

```go
// tests/benchmarks/collector_bench_test.go
func BenchmarkCollector_ProcessPacket(b *testing.B)
func BenchmarkCollector_WorkerPool(b *testing.B)
func BenchmarkCollector_SmallPCAP(b *testing.B)
func BenchmarkCollector_LargePCAP(b *testing.B)

// tests/benchmarks/decoder_bench_test.go
func BenchmarkDecoder_Ethernet(b *testing.B)
func BenchmarkDecoder_IPv4(b *testing.B)
func BenchmarkDecoder_TCP(b *testing.B)
func BenchmarkDecoder_HTTP(b *testing.B)
func BenchmarkDecoder_AllProtocols(b *testing.B)

// tests/benchmarks/reassembly_bench_test.go
func BenchmarkReassembly_InOrder(b *testing.B)
func BenchmarkReassembly_OutOfOrder(b *testing.B)
func BenchmarkReassembly_ManyConnections(b *testing.B)

// tests/benchmarks/io_bench_test.go
func BenchmarkWriter_Protobuf(b *testing.B)
func BenchmarkWriter_CSV(b *testing.B)
func BenchmarkWriter_Compression(b *testing.B)
func BenchmarkReader_Sequential(b *testing.B)
```

### 8.2 Throughput Tests

```go
// tests/benchmarks/throughput_test.go
func TestThroughput_PacketsPerSecond(t *testing.T)
func TestThroughput_MegabytesPerSecond(t *testing.T)
func TestThroughput_Scaling(t *testing.T)
```

### 8.3 Memory Profiling

```bash
# Memory profile commands
go test -memprofile=mem.prof ./collector/
go test -memprofile=mem.prof ./decoder/packet/
go test -memprofile=mem.prof ./reassembly/

# CPU profile commands
go test -cpuprofile=cpu.prof ./collector/
go test -bench=. -cpuprofile=cpu.prof ./tests/benchmarks/
```

### 8.4 Stress Tests

```go
// tests/benchmarks/stress_test.go
func TestStress_LongRunning(t *testing.T)        // Hours of operation
func TestStress_HighPacketRate(t *testing.T)     // 1M+ packets/sec
func TestStress_MemoryPressure(t *testing.T)     // Limited memory
func TestStress_ManyConnections(t *testing.T)    // 100k+ concurrent
```

**Baseline Performance Targets:**
- **Packet processing:** > 100k pps on 4-core system
- **PCAP reading:** > 1 GB/s on SSD
- **Memory usage:** < 500 MB for 1M packets
- **Stream reassembly:** < 100ms per connection

---

## E2E Tests

**Priority: Medium-Low**

### 9.1 CLI Command Tests

**Location:** `tests/e2e/`

Currently **0% coverage** for all commands. This is a critical gap.

```go
// tests/e2e/capture_test.go
func TestCLI_Capture_LiveInterface(t *testing.T)
func TestCLI_Capture_FromPCAP(t *testing.T)
func TestCLI_Capture_WithBPF(t *testing.T)
func TestCLI_Capture_OutputFormats(t *testing.T)
func TestCLI_Capture_Decoders(t *testing.T)
func TestCLI_Capture_Help(t *testing.T)

// tests/e2e/dump_test.go
func TestCLI_Dump_ReadAuditRecords(t *testing.T)
func TestCLI_Dump_FilterByType(t *testing.T)
func TestCLI_Dump_SelectFields(t *testing.T)
func TestCLI_Dump_Statistics(t *testing.T)

// tests/e2e/label_test.go
func TestCLI_Label_SuricataAlerts(t *testing.T)
func TestCLI_Label_CustomRules(t *testing.T)
func TestCLI_Label_OutputDataset(t *testing.T)

// tests/e2e/export_test.go
func TestCLI_Export_Prometheus(t *testing.T)
func TestCLI_Export_Metrics(t *testing.T)

// tests/e2e/collect_test.go
func TestCLI_Collect_ServerMode(t *testing.T)
func TestCLI_Collect_Authentication(t *testing.T)

// tests/e2e/agent_test.go
func TestCLI_Agent_Connection(t *testing.T)
func TestCLI_Agent_DataTransmission(t *testing.T)

// tests/e2e/proxy_test.go
func TestCLI_Proxy_ReverseProxy(t *testing.T)
func TestCLI_Proxy_Capture(t *testing.T)

// tests/e2e/util_test.go
func TestCLI_Util_Version(t *testing.T)
func TestCLI_Util_Validate(t *testing.T)
func TestCLI_Util_Convert(t *testing.T)

// tests/e2e/transform_test.go (maltego)
func TestCLI_Transform_Execution(t *testing.T)
func TestCLI_Transform_DataExtraction(t *testing.T)
```

### 9.2 Workflow Tests

```go
// tests/e2e/workflows_test.go
func TestWorkflow_CaptureAndAnalyze(t *testing.T) {
    // 1. Capture from PCAP
    // 2. Dump specific protocol
    // 3. Export to CSV
    // 4. Validate output
}

func TestWorkflow_LiveCaptureWithLabeling(t *testing.T) {
    // 1. Start capture on interface
    // 2. Generate traffic
    // 3. Stop capture
    // 4. Label with Suricata alerts
    // 5. Export labeled dataset
}

func TestWorkflow_DistributedCollection(t *testing.T) {
    // 1. Start collection server
    // 2. Start agent
    // 3. Agent sends data
    // 4. Server aggregates
    // 5. Export results
}
```

### 9.3 Error Handling Tests

```go
// tests/e2e/error_handling_test.go
func TestCLI_InvalidArguments(t *testing.T)
func TestCLI_MissingFiles(t *testing.T)
func TestCLI_PermissionDenied(t *testing.T)
func TestCLI_NetworkErrors(t *testing.T)
func TestCLI_DiskFull(t *testing.T)
func TestCLI_InterruptSignal(t *testing.T)
```

---

## Test Data Management

### 10.1 Test PCAP Collection

**Size Budget:** ~100 MB for essential fixtures

**Minimal Set (Tier 1):**
- 1 PCAP per major protocol (20 files, ~50 MB)
- 5 real-world scenarios (5 files, ~30 MB)
- 5 edge case files (5 files, ~10 MB)

**Extended Set (Tier 2):**
- Additional protocol variations
- Attack scenarios
- Performance test files (large)

**Storage:**
- Essential fixtures: In repo (`tests/fixtures/pcaps/`)
- Large files: External (download on demand, CI cache)
- Synthetic generation: Generate programmatically where possible

### 10.2 Golden File Management

```bash
tests/fixtures/golden/
├── csv/
│   ├── http_simple/
│   │   ├── Ethernet.csv
│   │   ├── IPv4.csv
│   │   ├── TCP.csv
│   │   ├── HTTP.csv
│   │   └── Connection.csv
│   └── ...
├── json/
└── proto/
```

**Version Control:**
- Store golden files in Git
- Update with `make test-golden-update`
- Review diffs carefully in PRs

### 10.3 Test Database Files

Create minimal test databases:

```
tests/fixtures/databases/
├── geoip/
│   ├── test-geoip.mmdb        # Small subset for testing
├── mac/
│   ├── test-mac-vendors.csv   # Sample MAC addresses
├── ja3/
│   ├── test-ja3.json          # Known JA3 fingerprints
├── service-probes/
│   ├── test-nmap-probes       # Sample service probes
└── dhcp/
    └── test-dhcp-fingerprints.csv
```

**Generation:**
```bash
make test-databases-generate  # Create minimal test DBs
```

---

## CI/CD Integration

### 11.1 GitHub Actions Workflow

```yaml
# .github/workflows/test.yml
name: Test Suite

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.23'
      
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y libpcap-dev
      
      - name: Run unit tests
        run: make test-unit
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.out

  integration-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v3
      - name: Run integration tests
        run: make test-integration

  regression-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v3
      - name: Download test fixtures
        run: make fixtures-download
      - name: Run regression tests
        run: make test-regression
      - name: Compare with golden files
        run: make test-regression-verify

  performance-tests:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/master'
    steps:
      - uses: actions/checkout@v3
      - name: Run benchmarks
        run: make test-bench
      - name: Store benchmark results
        uses: benchmark-action/github-action-benchmark@v1

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: golangci/golangci-lint-action@v3
```

### 11.2 Makefile Targets

```makefile
# Makefile

.PHONY: test test-unit test-integration test-regression test-bench test-all

# Run all tests
test-all: test-unit test-integration test-regression

# Unit tests (fast, no external dependencies)
test-unit:
	go test -short -race -coverprofile=coverage.out ./...

# Integration tests (with test fixtures)
test-integration:
	go test -v -tags=integration ./tests/integration/...

# Regression tests (compare with golden files)
test-regression:
	go test -v -tags=regression ./tests/regression/...

test-regression-verify:
	./scripts/verify-golden-files.sh

test-regression-update:
	UPDATE_GOLDEN=1 go test -v -tags=regression ./tests/regression/...

# Performance benchmarks
test-bench:
	go test -bench=. -benchmem -cpuprofile=cpu.prof ./tests/benchmarks/...

# Coverage report
test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Generate test fixtures
fixtures-generate:
	go run ./helpers/pcap_generator.go

# Download large test fixtures
fixtures-download:
	./scripts/download-test-fixtures.sh

# Generate test databases
test-databases-generate:
	go run ./helpers/generate_test_dbs.go

# Run tests with race detector
test-race:
	go test -race ./...

# Run tests with memory sanitizer
test-msan:
	CC=clang go test -msan ./...
```

### 11.3 Coverage Tracking

**Target:** 80% overall coverage

**Per-Package Minimums:**
- Critical packages (collector, decoder, types): 85%
- Important packages (io, reassembly): 75%
- Utility packages: 70%
- Commands: 60%

**Coverage Enforcement:**
```bash
# Fail CI if coverage drops below threshold
go test -cover -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//' | \
  awk '{if ($1 < 80) exit 1}'
```

---

## Implementation Roadmap

### Phase 1: Foundation (Weeks 1-4)

**Goal:** Fix existing issues, establish test infrastructure

**Tasks:**
1. **Week 1: Fix Critical Bugs**
   - [ ] Fix 4 failing reassembly tests
   - [ ] Fix DBS package build errors (unused variables)
   - [ ] Fix DPI build issues or make optional
   - [ ] Fix resolver tests (provide test data or mock)
   
2. **Week 2: Test Infrastructure**
   - [ ] Create `tests/` directory structure
   - [ ] Implement test helper library (`helpers/`)
   - [ ] Create minimal test PCAP collection (Tier 1)
   - [ ] Setup golden file infrastructure
   - [ ] Create Makefile targets

3. **Week 3: Core Package Tests (Priority 1)**
   - [ ] Collector package: 85% coverage
   - [ ] Types package: 80% coverage
   - [ ] I/O package: 85% coverage
   
4. **Week 4: Decoder Foundation**
   - [ ] Create test template for protocol decoders
   - [ ] Test top 10 protocol decoders (Tier 1)
   - [ ] Fix and enhance existing decoder tests

**Deliverable:** Working test infrastructure with 40%+ overall coverage

---

### Phase 2: Core Coverage (Weeks 5-8)

**Goal:** Achieve 70% coverage on critical paths

**Tasks:**
5. **Week 5-6: Protocol Decoders**
   - [ ] Test Tier 1 packet decoders (ethernet, ip, tcp, udp, dns, http, tls)
   - [ ] Test Tier 2 packet decoders (dhcp, arp, icmp)
   - [ ] Achieve 75% coverage on decoder/packet package
   
6. **Week 6-7: Stream Decoders**
   - [ ] Fix and enhance HTTP stream decoder tests
   - [ ] Test TLS stream decoder
   - [ ] Test SSH stream decoder
   - [ ] Enhance credentials decoder tests (from 52.8%)
   - [ ] Fix service, exploit, vulnerability tests (index issues)
   
7. **Week 8: Reassembly & Integration**
   - [ ] Achieve 90% coverage on reassembly package
   - [ ] Create first integration tests
   - [ ] Test full pipeline (pcap → decoders → output)

**Deliverable:** 70% overall coverage, core functionality tested

---

### Phase 3: Regression & Commands (Weeks 9-12)

**Goal:** Regression suite and CLI command coverage

**Tasks:**
8. **Week 9-10: Regression Tests**
   - [ ] Create golden file suite for all protocols
   - [ ] Implement regression test framework
   - [ ] Test output format consistency (CSV, JSON, protobuf)
   - [ ] Create baseline performance benchmarks
   
9. **Week 11: CLI Commands (Part 1)**
   - [ ] Test `capture` command (most critical)
   - [ ] Test `dump` command
   - [ ] Test `label` command
   - [ ] E2E workflow tests
   
10. **Week 12: CLI Commands (Part 2)**
    - [ ] Test `export` command
    - [ ] Test `collect` and `agent` commands
    - [ ] Test `proxy` command
    - [ ] Test `util` command

**Deliverable:** Regression suite, 60%+ command coverage, 75% overall coverage

---

### Phase 4: Completeness (Weeks 13-16)

**Goal:** Achieve 80%+ coverage, comprehensive test suite

**Tasks:**
11. **Week 13-14: Protocol Completeness**
    - [ ] Test Tier 3 packet decoders
    - [ ] Test remaining stream decoders
    - [ ] Test industrial protocols (Modbus, CIP, ENIP)
    - [ ] Edge case and malformed packet tests
    
12. **Week 15: Performance & Stress**
    - [ ] Comprehensive benchmark suite
    - [ ] Memory profiling and optimization
    - [ ] Throughput tests
    - [ ] Stress tests (long-running, high-volume)
    
13. **Week 16: Polish**
    - [ ] Test Maltego transforms
    - [ ] Test analyze package
    - [ ] Final coverage push (80%+)
    - [ ] Documentation and test guides

**Deliverable:** Complete test suite with 80%+ coverage

---

### Phase 5: Maintenance & Automation (Ongoing)

**Tasks:**
- [ ] CI/CD pipeline with all test categories
- [ ] Automated coverage reporting
- [ ] Performance regression detection
- [ ] Test maintenance guide
- [ ] Contributor test guidelines

---

## Success Metrics

### Coverage Targets

**Overall:** 80% code coverage

**By Package:**
| Package | Current | Target | Priority |
|---------|---------|--------|----------|
| collector | 0% (build fail) | 85% | Critical |
| decoder/packet | 0% (build fail) | 75% | Critical |
| decoder/stream | ~15% avg | 70% | Critical |
| types | 0.8% | 80% | Critical |
| io | 19.7% | 85% | High |
| reassembly | 68.9% | 90% | High |
| encoder | 64.0% | 75% | Medium |
| delimited | 69.0% | 80% | Medium |
| logger | 89.5% | 95% | Low (good) |
| utils | 29.3% | 85% | Medium |
| resolvers | 0% (build fail) | 75% | High |
| label | 49.3% | 80% | Medium |
| cmd/* | 0% | 60% | High |
| maltego | 0% (build fail) | 50% | Low |

### Quality Metrics

**Test Stability:**
- ✅ 0 flaky tests
- ✅ All tests pass on clean checkout
- ✅ No test dependencies on external services (use mocks)

**Test Performance:**
- ✅ Unit tests: < 30s total runtime
- ✅ Integration tests: < 5min
- ✅ Full suite: < 15min

**Regression Detection:**
- ✅ Detect protocol decoder changes
- ✅ Detect output format changes
- ✅ Detect performance regressions (>10% slower)

### Maintenance Metrics

**Test Quality:**
- ✅ All tests have clear names and documentation
- ✅ Test failures provide actionable error messages
- ✅ Tests are independent (can run in any order)

**Developer Experience:**
- ✅ Easy to run specific test categories
- ✅ Fast feedback loop (< 30s for unit tests)
- ✅ Clear test failure diagnostics

---

## Appendix A: Test Data Sources

### Public PCAP Repositories

1. **Wireshark Sample Captures**
   - URL: https://wiki.wireshark.org/SampleCaptures
   - License: Various (check individual files)
   - Usage: Protocol-specific test cases

2. **NETRESEC**
   - URL: https://www.netresec.com/pcap/
   - License: Permissive
   - Usage: Real-world traffic samples

3. **Malware Traffic Analysis**
   - URL: https://malware-traffic-analysis.net
   - License: Public samples
   - Usage: Attack/malware detection tests

4. **PacketLife**
   - URL: https://packetlife.net/captures/
   - License: Public
   - Usage: Various protocol captures

### Generating Synthetic PCAPs

```go
// helpers/pcap_generator.go
package helpers

import "github.com/dreadl0ck/gopacket"

// GenerateHTTPRequest creates a synthetic HTTP GET request packet
func GenerateHTTPRequest(config HTTPConfig) ([]byte, error)

// GenerateTCPHandshake creates a complete TCP 3-way handshake
func GenerateTCPHandshake(config TCPConfig) ([][]byte, error)

// GenerateDNSQuery creates a DNS query/response pair
func GenerateDNSQuery(config DNSConfig) ([][]byte, error)
```

---

## Appendix B: Testing Best Practices

### Test Naming Convention

```go
// Format: Test<Component>_<Scenario>
func TestCollector_InitWithValidConfig(t *testing.T)
func TestDecoder_MalformedPacket(t *testing.T)

// Format: Benchmark<Component>_<Operation>
func BenchmarkDecoder_ProcessPacket(b *testing.B)

// Format: Example<Component>_<UseCase>
func ExampleCollector_CollectPcap()
```

### Table-Driven Tests

```go
func TestProtocolDecoder(t *testing.T) {
    tests := []struct {
        name    string
        input   []byte
        want    *types.Record
        wantErr bool
    }{
        {"valid packet", validData, expectedRecord, false},
        {"malformed", malformedData, nil, true},
        {"edge case", edgeCaseData, edgeRecord, false},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := decoder.Decode(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("Decode() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("Decode() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Test Isolation

```go
func TestWithIsolation(t *testing.T) {
    // Create isolated temp directory
    tmpDir := t.TempDir()  // Automatically cleaned up
    
    // Use test-specific config
    config := testConfig()
    config.Out = tmpDir
    
    // Test logic here
}
```

### Parallel Tests

```go
func TestCanRunInParallel(t *testing.T) {
    t.Parallel()  // Mark test as safe to run in parallel
    
    // Test logic here (must be isolated)
}
```

---

## Appendix C: Quick Start Guide

### Running Tests Locally

```bash
# Install dependencies
make deps

# Run all unit tests
make test-unit

# Run tests for specific package
go test -v ./collector/

# Run tests with coverage
make test-coverage

# Run specific test
go test -v -run TestCollector_Init ./collector/

# Run benchmarks
make test-bench

# Update golden files (after verifying changes are correct)
make test-regression-update
```

### Adding a New Test

1. **Create test file** (if doesn't exist):
   ```bash
   touch decoder/packet/myprotocol_test.go
   ```

2. **Use test template:**
   ```go
   package packet_test
   
   import (
       "testing"
       "github.com/dreadl0ck/netcap/decoder/packet"
   )
   
   func TestMyProtocol_Decode(t *testing.T) {
       // Test implementation
   }
   ```

3. **Add test fixture** (if needed):
   ```bash
   # Add PCAP to fixtures
   cp my_test.pcap tests/fixtures/pcaps/protocols/
   
   # Add golden file
   # (will be generated automatically on first run with UPDATE_GOLDEN=1)
   ```

4. **Run and verify:**
   ```bash
   go test -v ./decoder/packet/ -run TestMyProtocol
   ```

### Debugging Failing Tests

```bash
# Run with verbose output
go test -v ./package/

# Run with race detector
go test -race ./package/

# Print test coverage
go test -cover ./package/

# Generate coverage profile
go test -coverprofile=coverage.out ./package/
go tool cover -html=coverage.out
```

---

## Appendix D: Reviewer Checklist

When reviewing test-related PRs, ensure:

- [ ] Tests cover both success and failure paths
- [ ] Tests use table-driven approach where applicable
- [ ] Test names clearly describe what is being tested
- [ ] Tests are isolated and don't depend on execution order
- [ ] No hardcoded paths (use t.TempDir(), fixtures)
- [ ] Mocks are used for external dependencies
- [ ] Benchmarks include b.ReportAllocs() for memory tracking
- [ ] Coverage hasn't decreased (check CI report)
- [ ] New features include tests
- [ ] Regression tests updated if outputs changed
- [ ] Golden files updated if intentional changes

---

**Document Version:** 1.0  
**Last Updated:** October 21, 2025  
**Maintained By:** Netcap Development Team  
**Questions/Feedback:** Open an issue on GitHub

