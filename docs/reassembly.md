# TCP reassembly

Application messages can span TCP segments, share one segment or arrive with
retransmissions/out-of-order delivery. Netcap assembles directional streams
before protocol-specific parsing; a packet boundary is not an HTTP/DNP3/Modbus
message boundary.

```sh
net capture -read traffic.pcap -out streams -reassemble-connections=true \
  -conns -dpi=false
```

## Boundaries and missing bytes

| Condition | Consequence |
| --- | --- |
| Missing SYN/initial payload | Direction/boundary can be uncertain; inspect parser-specific states |
| Known-size gap | A parser may have a restricted resynchronization rule |
| Unknown-size gap | Parsing may stop rather than guess framing |
| Retransmission | Reassembly suppresses/reconciles bytes according to its policy |
| Per-direction buffer limit | Evidence can be incomplete when bounds are reached |
| Connection finalization | Stream records and alerts may only become visible on completion/flush |

Go v0.15.2's default maximum buffered size is 10 MiB per direction. Zero-valued
page limits can mean unlimited; [resource budgets](workers.md) are not a global
memory guarantee. Use the installed help and health sidecars for actual policy.

## Inspect the evidence

With `-conns`, `stream-evidence/stream-*/` contains `client.bin`, `server.bin`
and a manifest recording direction, offsets, times, gaps and UDP boundaries where
applicable. The display transcript is separate. Never remove gap markers and
pass concatenated bytes to an experiment as if they were contiguous.

Protocol parsers differ. Modbus stops or resynchronizes only at defined points;
DNP3 CRC/framing evidence and HTTP recovery have their own limits. Read the
protocol-specific guide before interpreting `lost`, `unmatched` or a recovered
record as complete coverage.

`TCPReassemblyHealth.json` qualifies checksum policy and rejections. Malformed
input, encrypted payloads and unsupported protocols can all yield no application
records. [Capture health](evidence.md) helps distinguish missing visibility from
an observed negative.
