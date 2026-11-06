# Filtering

Choose a filter stage deliberately. BPF selects packets; decoder options select
producers; typed expressions select records. These controls are not equivalent.

## Packet filters

```sh
net capture -read traffic.pcap -out dns-audit -bpf 'udp port 53' -dpi=false
```

BPF requires a working platform libpcap/Npcap path. It can remove the SYN,
response or handshake a decoder needs. Filtered offline input does not promise
the same PCAPNG interface metadata as unfiltered input; inspect scope health.

## Post-capture expressions

Start by discovering fields:

```sh
net dump -read analysis/UDP.ncap.gz -fields
net dump -read analysis/UDP.ncap.gz -filter 'DstPort == 9999' -json
net dump -read analysis/Connection.ncap.gz \
  -filter 'DstPort == "443"' -json
```

`dump` compiles the expression for the file's type. Connection and TCP/UDP
ports have different types. Parenthesize combined conditions and quote the
whole expression for the shell. Match semantics come from the installed
expr-language environment and helpers, not SQL or BPF syntax.

| Expression shape | Meaning |
| --- | --- |
| `DstPort == 443 && SYN && !ACK` | TCP packet condition; not proof of a completed session |
| `DstPort == "443"` | Connection record port equality |
| `InSubnet(SrcIP, "192.0.2.0/24")` | Network helper on a record exposing string `SrcIP` |

Do not reuse fields across record types without checking `dump -fields`.
[Rules](RULES_ENGINE.md) use typed record expressions too, but have additional
threshold/sequence/action behavior.

## Capture-time compatibility filter

In Go v0.15.2, `capture -filter` is compiled against TCP. Compilation warns
rather than failing the capture, and evaluation errors can pass records through;
other record types are not generally filtered. It is **not** an all-record
filter or a data-minimization boundary. For a predictable analysis workflow,
retain the capture and apply `dump -filter` to an explicit audit type.

## Preserve provenance

Record the input hash, command, expression, version and output hash when sharing
an export. A selected record set is not a selected packet capture. Use
[packet evidence](evidence.md) when the recipient needs original packet bytes
and a selection manifest.
