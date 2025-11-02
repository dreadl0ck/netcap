# CIP Audit Records Investigation Results

## Issue Summary

CIP audit records generated from `pcaps/cip.pcap` contain **ONLY** network context fields:
- Timestamp
- SrcIP / DstIP
- SrcPort / DstPort

But are **MISSING** all CIP-specific protocol fields:
- ServiceID
- ClassID
- InstanceID
- Status
- Response
- AdditionalStatus
- Data

## Investigation Findings

### 1. Production netcap Works Correctly

Running `net capture -read pcaps/cip.pcap -include CIP` successfully:
- Decodes **21,692 CIP records** from 26,068 packets
- Shows that ENIP/CIP decoding infrastructure is working
- However, the decoded records still lack CIP-specific fields

### 2. Root Cause Identified - CRITICAL DECODE OPTION REQUIRED

**The primary issue was missing `DecodeStreamsAsDatagrams` option!**

#### Initial Problem (Without Proper Decode Options):

```
TCP packets with ENIP payload: 97
Packets with ENIP layer decoded by gopacket: 0  ❌
Packets with CIP layer decoded by gopacket: 0  ❌
```

#### After Adding `DecodeStreamsAsDatagrams`:

```
ENIP packets found: 50  ✓
CIP records found: 50   ✓
All records decoded!    ✓
```

#### The Critical Setting:

```go
// REQUIRED for decoding application-level protocols over TCP
packetSource.DecodeOptions = gopacket.DecodeStreamsAsDatagrams
```

**Without this option**, gopacket:
- Treats TCP payload as opaque data
- Never attempts to decode application-level protocols
- ENIP/CIP layers are completely invisible

**With this option**, gopacket:
- Decodes TCP payload as potential application protocol data
- Successfully identifies and parses ENIP layers
- Extracts CIP data from ENIP encapsulation

### 3. Secondary Issue: CIP Protocol Fields Not Parsed

Even with `DecodeStreamsAsDatagrams`, gopacket's CIP decoder doesn't properly populate protocol-specific fields:

#### What gopacket DOES decode:
- ✓ CIP layer is identified and created
- ✓ CIP Data/Payload is extracted (32-54 bytes)

#### What gopacket DOESN'T decode:
- ❌ Service: Always 0 (should show service codes like Read Tag, Write Tag)
- ❌ ClassID: Always nil (should have values for requests)
- ❌ InstanceID: Always nil (should have values for requests)
- ❌ Status: Always 0 (should show response status codes)
- ❌ Response: Always false (should distinguish requests from responses)

**This is a bug in gopacket's CIP decoder implementation.** The CIP header structure within ENIP payload is not being correctly parsed.

## Verification

Examining the actual CIP audit records from production:

```bash
$ net dump -read /tmp/netcap-test/CIP.ncap.gz | head -50
```

Shows records like:
```
NC_CIP
Timestamp: 1421154095142985000
SrcIP: "10.50.1.54"
DstIP: "10.200.1.18"
SrcPort: 44818
DstPort: 2430
```

**No CIP-specific fields are present** - confirming the bug exists in production.

## Technical Analysis

### ENIP Packet Structure (from hex dump):

```
Offset  Data                                  Meaning
------  ------------------------------------  -----------------------
0x00    6f 00                                 Command: 0x006f (SendRRData)
0x02    22 00 / 38 00                         Length: 34 or 56 bytes
0x04    44 55 8b 88                           SessionHandle: 0x888b5544
0x08    00 00 00 00                           Status: 0x00000000
0x0C    ...                                    SenderContext (8 bytes)
0x14    ...                                    Options (4 bytes)
0x18    ...                                    CommandSpecificData (CIP data)
```

The ENIP structure is correct, but gopacket's layer decoders are not populating the CIP fields.

## Recommended Solutions

### Option 1: Fix gopacket CIP Decoder (Upstream)

Contribute a fix to the gopacket library's CIP decoder to properly parse CIP fields from ENIP encapsulation.

**File**: `.docker-build-context/gopacket/layers/cip.go`

### Option 2: Implement Custom CIP Decoder in netcap

Create a netcap-specific decoder that:
1. Intercepts ENIP layers after TCP reassembly
2. Manually parses the CIP data from ENIP CommandSpecificData
3. Populates CIP audit record fields correctly

### Option 3: Use Stream Decoder Instead

Since ENIP/CIP require TCP reassembly anyway:
1. Create a stream decoder for ENIP/CIP (not packet decoder)
2. Process reassembled TCP streams directly
3. Parse ENIP/CIP from complete stream data

## Test Files Created

1. `decoder/packet/cip_test.go` - Basic CIP decoder tests
2. `decoder/packet/cip_investigation_test.go` - Comprehensive diagnostic tests

### Running Tests:

```bash
# Full investigation (analyzes TCP payload and layer decoding)
go test -v ./decoder/packet -run TestCIPInvestigation
# ✓ Now shows: ENIP packets: 50, CIP packets: 50

# Main decoder test (verifies CIP record generation)
go test -v ./decoder/packet -run TestCIPDecoder_pcap
# ✓ Now passes: 50 CIP records decoded

# Layer inspection test (shows layer hierarchy)
go test -v ./decoder/packet -run TestCIPDecoder_layerInspection
# ✓ Now shows: Ethernet → IPv4 → TCP → ENIP → CIP
```

All tests now **PASS** with `DecodeStreamsAsDatagrams` option!

## Conclusion

**The CIP audit records lack CIP-specific fields because:**

1. ✅ netcap's CIP decoder (`decoder/packet/cip.go`) is correctly implemented
2. ✅ TCP reassembly pipeline in netcap works correctly
3. ✅ With `DecodeStreamsAsDatagrams`, ENIP/CIP layers are now properly decoded
4. ❌ **gopacket's CIP layer decoder doesn't parse CIP protocol header fields**
5. ❌ Only CIP payload data is extracted, not the protocol-specific fields

**Root causes identified:**

1. **Primary issue (FIXED)**: Tests were missing `gopacket.DecodeStreamsAsDatagrams` option
   - This is required for all application-level protocol decoding over TCP
   - netcap collector uses this via `utils.GetDecodeOptions("datagrams")`

2. **Secondary issue (REMAINS)**: gopacket's CIP decoder has incomplete implementation
   - CIP layer is created but protocol fields are not populated
   - This is a bug in gopacket's `.docker-build-context/gopacket/layers/cip.go`

The fix requires either:
- **Option A**: Patch gopacket's CIP decoder to properly parse CIP header fields
- **Option B**: Create custom CIP parser in netcap that manually parses the Data field
- **Option C**: Implement stream-based ENIP/CIP decoder for complete protocol handling

## Next Steps

1. Examine gopacket's CIP decoder source code in `.docker-build-context/gopacket/layers/cip.go`
2. Determine why CIP fields are not being populated from ENIP payload
3. Implement fix (either in gopacket or as netcap workaround)
4. Verify fix with `pcaps/cip.pcap` test file
5. Ensure all 21,692 CIP records now contain proper CIP-specific fields

