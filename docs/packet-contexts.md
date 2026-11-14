# Packet contexts

`PacketContext` holds related IP and port information on supported audit records. It lets a transport or application record keep the endpoints that belong to another decoded layer. `capture` enables `-context` by default.

```sh
net capture -read traffic.pcap -out context-audit -context=true -dpi=false
net dump -read context-audit/UDP.ncap.gz -fields
net dump -read context-audit/UDP.ncap.gz -json
```

The [first capture](quickstart.md) gives you a UDP file to try this on. CSV output flattens the context fields into columns such as `SrcIP` and `DstIP`. `dump -fields` prints one selectable field per line. Transport fields that are already on the record are not repeated in the context.

| Context                | Notes                                                          |
| ---------------------- | -------------------------------------------------------------- |
| Packet endpoints       | Observed addresses and ports; not a verified asset identity    |
| Connection orientation | Can differ from the direction of an individual packet          |
| Community ID           | Correlates flows across tools; not unique per observation      |
| Evidence link          | A scoped reference with provenance, more than shared endpoints |

The full schema is in `types/netcap.proto`. Turning context off removes information you need for later joins; it does not anonymize retained payloads. See [hosts and identity](host-identity.md) and [evidence linking](evidence.md).
