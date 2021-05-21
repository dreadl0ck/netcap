---
description: TCP stream reassembly
---

# Reassembly

## Implementation

For reassembling TCP streams the gopacket/reassembly implementation is used. This allows to parse application layer protocols such as HTTP and POP3. The reassembly package currrently only implements reassembling stream over IPv4. To overcome this limitation for HTTP capture, you can use the **proxy** tool.

{% page-ref page="http-proxy.md" %}

## Architecture

The gopacket reassembly implementation leaves several options for using it.

Netcap currently uses one dedicated assembler for each worker and a single shared connection pool for all streams.

Another option would be using a dedicated assembler for each worker for each L7 protocol with a shared stream pool for that specific protocol. This would potentially decrease lock contention for the reassembly, and might be implemented to improve performance in future versions.

## Configuration

The following fields of the **decoder.Config** affect the TCP stream reassembly:

```go
// Interval to apply connection flushes
FlushEvery         int

// Do not use IPv4 defragger
NoDefrag           bool

// Dont verify the packet checksums
Checksum           bool

// Dont check TCP options
NoOptCheck         bool

// Ignore TCP state machine errors
IgnoreFSMerr       bool

// TCP state machine allow missing init in three way handshake
AllowMissingInit   bool

// Toggle debug mode
Debug              bool

// Dump packet contents as hex for debugging
HexDump            bool

// Wait until all connections finished processing when receiving shutdown signal
WaitForConnections bool

// Write incomplete HTTP responses to disk when extracting files
WriteIncomplete    bool
```

## Debugging

To see debug output for the reassembly, run with the **-debug** flag and check the **reassembly.log** file.

For more general troubleshooting advice, please refer to the Troubleshooting page:

{% page-ref page="troubleshooting.md" %}

