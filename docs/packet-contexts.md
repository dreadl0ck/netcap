# Packet Contexts

`PacketContext` carries related IP/port information on supported audit records.
It allows a transport or application record to retain endpoints that otherwise
belong to another decoded layer. Capture enables `-context` by default.

```sh
net capture -read traffic.pcap -out context-audit -context=true -dpi=false
net dump -read context-audit/UDP.ncap.gz -fields
net dump -read context-audit/UDP.ncap.gz -json
```

Use [the synthetic capture](quickstart.md) for a known UDP example. CSV rendering
flattens supported context fields into columns such as `SrcIP` and `DstIP`;
`dump -fields` prints one selectable field per line. Duplicate transport fields
need not be repeated in context.

| Context | Boundary |
| --- | --- |
| Packet endpoints | Observed addresses/ports, not authenticated asset identity |
| Connection orientation | Can differ from an individual packet's direction |
| Community ID | Cross-tool flow correlation, not a globally unique observation id |
| Evidence link | Scoped reference plus provenance, beyond merely sharing endpoints |

Read the current schema in `types/netcap.proto`. A historical four-field excerpt
is not the full contract for every record. Disabling context reduces information
available for later joins; it does not anonymize retained payloads. See
[hosts and identity](host-identity.md) and [evidence linking](evidence.md).
