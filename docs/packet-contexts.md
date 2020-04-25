---
description: Preserve information about other layers on audit records
---

# Packet Contexts

Netcap v0.4.3 added PacketContexts, a new feature to preserve additional information on audit records.

This need originates from a core concept of Netcap: separating the results based on the different protocols, which results in audit records like TCP not providing any IP address information, since they only provide information about the TCP protocol which operates at the Transport Layer.

A packet context looks as follows:

```erlang
message PacketContext {
    string SrcIP    = 1;
    string DstIP    = 2;
    string SrcPort  = 3;
    string DstPort  = 4;
}
```

Many audit record types \(e.g: IPv4, IPv6, TCP, UDP, ICMPv4, ICMPv6, SCTP, DNS, DHCP, SIP etc\) now have an addional field called context, which will contain a PacketContext that describes the flow where the packet originated from, if context capture is enabled.

When generating a CSV representation the fields from the PacketContext are flattened, which means they will be shown as if they are direct member of the dumped audit record, e.g:

```text
$ net dump -read UDP.ncap.gz -fields
Timestamp,SrcPort,DstPort,Length,Checksum,PayloadEntropy,PayloadSize,Payload,SrcIP,DstIP
```

If the audit record already has information that would be duplicated by the PacketContext \(for example Port information for UDP\), this information is cleared on the context to avoid repetition.

Context capture is enabled by default and can be controlled using the **-context** flag.

