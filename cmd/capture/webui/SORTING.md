# Hierarchical Sorting and Filtering

The Web UI now provides hierarchical sorting of audit records by layer type and filters out empty log files for a cleaner, more organized view.

## Features

### 1. Hierarchical Sorting of Audit Records

Audit records are sorted according to the OSI model and netcap's layer organization, matching the output of `net util -decoders`:

**Sort Order:**
1. **Link Layer** (ARP, Ethernet, Dot1Q, LLC, USB, etc.)
2. **Network Layer** (IPv4, IPv6, ICMPv4, ICMPv6, GRE, MPLS, etc.)
3. **Transport Layer** (TCP, UDP, SCTP)
4. **Application Layer** (DNS, DHCP, NTP, SIP, TLS, Connection, Profiles, etc.)
5. **Stream Decoders** (HTTP, POP3, SMTP, SSH)
6. **Abstract Decoders** (Alert, Credentials, Exploit, File, Mail, Service, Software, Vulnerability)
7. **Unknown/Other** (any unrecognized types)

Within each layer, protocols are sorted alphabetically for easy navigation.

### 2. Layer Column

The Audit Records table now includes a "Layer" column showing which encapsulation layer each protocol belongs to:

| Layer             | Type       | Filename      | Records | Size  | Actions |
|-------------------|------------|---------------|---------|-------|---------|
| Link Layer        | Ethernet   | Ethernet.ncap | 1,234   | 2.1MB | [View]  |
| Link Layer        | ARP        | ARP.ncap      | 45      | 12KB  | [View]  |
| Network Layer     | IPv4       | IPv4.ncap     | 5,678   | 8.3MB | [View]  |
| Network Layer     | ICMPv4     | ICMPv4.ncap   | 89      | 56KB  | [View]  |
| Transport Layer   | TCP        | TCP.ncap      | 9,012   | 15MB  | [View]  |
| Application Layer | DNS        | DNS.ncap      | 234     | 123KB | [View]  |
| Stream Decoders   | HTTP       | HTTP.ncap     | 567     | 2.5MB | [View]  |
| Abstract Decoders | Software   | Software.ncap | 12      | 8KB   | [View]  |

### 3. Empty Log File Filtering

Log files with zero bytes are now automatically filtered out and won't appear in the Logs page. This prevents clutter from log files that were created but never written to.

**Before:** All `.log` files shown, including empty ones  
**After:** Only non-empty log files displayed

## Implementation Details

### Backend Sorting (`sorting.go`)

```go
type LayerType int

const (
    LayerLink LayerType = iota
    LayerNetwork
    LayerTransport
    LayerApplication
    LayerStream
    LayerAbstract
    LayerUnknown
)
```

Protocol categorization is based on netcap's decoder organization:

**Link Layer Protocols:**
- ARP, Ethernet, Dot1Q, LLC, CiscoDiscovery, LinkLayerDiscovery, etc.

**Network Layer Protocols:**
- IPv4, IPv6, ICMPv4, ICMPv6, GRE, MPLS, IPSec, IGMP, etc.

**Transport Layer Protocols:**
- TCP, UDP, SCTP

**Application Layer Protocols:**
- DNS, DHCPv4, DHCPv6, NTP, SIP, TLS, Connection, DeviceProfile, IPProfile, etc.

**Stream Decoders:**
- HTTP, POP3, SMTP, SSH

**Abstract Decoders:**
- Alert, Credentials, Exploit, File, Mail, Service, Software, Vulnerability

### Sorting Algorithm

```go
func SortAuditFiles(files []AuditFileInfo) {
    // Sort by layer first, then alphabetically within layer
    for i := 0; i < len(files); i++ {
        for j := i + 1; j < len(files); j++ {
            layerI := GetLayerType(files[i].Type)
            layerJ := GetLayerType(files[j].Type)
            
            if layerI > layerJ {
                files[i], files[j] = files[j], files[i]
            } else if layerI == layerJ {
                if files[i].Type > files[j].Type {
                    files[i], files[j] = files[j], files[i]
                }
            }
        }
    }
}
```

### Empty Log File Filtering

```go
for _, file := range files {
    info, err := file.Info()
    if err != nil {
        continue
    }
    
    // Skip empty log files
    if info.Size() == 0 {
        continue
    }
    
    logFiles = append(logFiles, FileInfo{...})
}
```

## Benefits

### 1. Better Organization
- Audit records grouped by network stack layer
- Easier to find specific protocol types
- Matches familiar OSI model structure

### 2. Progressive Detail
- Start with low-level (Link Layer)
- Progress through network stack
- End with high-level abstractions
- Natural flow from basic → advanced

### 3. Custom Abstractions Last
- Core protocols shown first
- Abstract/derived data at the end
- Separates raw captures from analysis results

### 4. Cleaner Logs View
- No empty log files cluttering the list
- Only meaningful logs displayed
- Faster to find relevant information

## Example Output

### Before Sorting (Alphabetical)
```
Alert
ARP
Connection
Credentials
DNS
Ethernet
Exploit
File
HTTP
ICMPv4
IPv4
Mail
Service
Software
TCP
TLSClientHello
UDP
Vulnerability
```

### After Hierarchical Sorting (By Layer)
```
─── Link Layer ───
ARP
Ethernet

─── Network Layer ───
ICMPv4
IPv4

─── Transport Layer ───
TCP
UDP

─── Application Layer ───
Connection
DNS
TLSClientHello

─── Stream Decoders ───
HTTP

─── Abstract Decoders ───
Alert
Credentials
Exploit
File
Mail
Service
Software
Vulnerability
```

## API Response

The `/api/files/audit` endpoint now includes layer information:

```json
[
  {
    "name": "Ethernet.ncap.gz",
    "path": "/tmp/output/Ethernet.ncap.gz",
    "size": 2145728,
    "modifiedTime": 1698345678,
    "isCompleted": false,
    "type": "Ethernet",
    "recordCount": 1234,
    "layer": "Link Layer"
  },
  {
    "name": "IPv4.ncap.gz",
    "path": "/tmp/output/IPv4.ncap.gz",
    "size": 8704512,
    "modifiedTime": 1698345678,
    "isCompleted": false,
    "type": "IPv4",
    "recordCount": 5678,
    "layer": "Network Layer"
  }
]
```

The array is pre-sorted by the backend, so the frontend receives protocols in the correct hierarchical order.

## Matching `net util -decoders`

This sorting matches the output of the netcap utility command:

```bash
./bin/net util -decoders
```

Which shows the same hierarchical structure:

```
Supported Audit Record Types by Encapsulation Level
====================================================

├── Link Layer
│   ├── ARP (Type: NC_ARP)
│   ├── Ethernet (Type: NC_Ethernet)
│   ...
│   └── Network Layer
│       ├── IPv4 (Type: NC_IPv4)
│       ├── IPv6 (Type: NC_IPv6)
│       ...
│       └── Transport Layer
│           ├── TCP (Type: NC_TCP)
│           ├── UDP (Type: NC_UDP)
│           ...
│           └── Application Layer
│               ├── DNS (Type: NC_DNS)
│               ...
├── Stream Decoders
│   ├── HTTP (Type: NC_HTTP)
│   ...
└── Abstract Decoders
    ├── Alert (Type: NC_Alert)
    ├── Credentials (Type: NC_Credentials)
    ...
```

The Web UI now presents audit records in the same logical order!

## Testing

```bash
cd /Users/pmieden/go/src/github.com/dreadl0ck/netcap

# Process a capture
./bin/net capture -read traffic.pcap -out /tmp/sorted -http localhost:8080
```

**Navigate to Audit Records page:**
- Protocols are grouped by layer
- Link Layer protocols appear first
- Abstract Decoders appear last
- Within each layer, alphabetically sorted

**Navigate to Logs page:**
- Only non-empty log files are shown
- No 0-byte files cluttering the view

