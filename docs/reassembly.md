---
description: TCP stream reassembly
---

# Reassembly

For reassembling TCP streams the gopacket/reassembly is used. 

> Note that there is currently only support for IPv4 stream reassembly!

The following fields of the **encoder.Config** affect the TCP stream reassembly:

```text
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

// Toogle Debug Mode
Debug              bool

// Dump packets as hex for debugging
HexDump            bool

// Wait until all connections finished processing when receiving shutdown signal
WaitForConnections bool

// Save incomplete http reponses and requests 
WriteIncomplete    bool
```

To see debug output for the reassembly, run with the **-debug** flag and check the **reassembly.log** file.

