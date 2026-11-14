# Filtering

Three things can narrow what you see, and they work at different stages. BPF drops packets before decoding. Decoder options decide which record types are produced. Typed expressions filter records after capture.

## Packet filters

Keep only DNS from an office LAN capture:

```sh
net capture -read office-lan.pcap -out dns-audit -bpf 'udp port 53' -dpi=false
```

BPF needs libpcap (Npcap on Windows). It can remove the SYN, the response or the handshake a decoder needs, so filter packets only when you are sure you do not need that context. PCAPNG interface metadata may be missing from filtered output, so check the scope health.

## Post-capture expressions

List the fields of a record file first, then filter:

```sh
net dump -read analysis/UDP.ncap.gz -fields
net dump -read analysis/UDP.ncap.gz -filter 'DstPort == 53' -json
net dump -read analysis/Connection.ncap.gz \
  -filter 'DstPort == "443"' -json
```

`dump` compiles the expression for the type of the file it reads. TCP and UDP ports are numbers, Connection ports are strings, so the two filters above are written differently. Wrap combined conditions in parentheses and quote the whole expression for your shell. The syntax is the expr language, not SQL or BPF.

| Expression                          | Matches                                        |
| ----------------------------------- | ---------------------------------------------- |
| `DstPort == 443 && SYN && !ACK`     | TCP packets that open a connection to port 443 |
| `DstPort == "443"`                  | Connection records with destination port 443   |
| `InSubnet(SrcIP, "192.168.1.0/24")` | Records whose `SrcIP` is in the subnet         |

Check `dump -fields` before you reuse a field name on another record type. [Rules](RULES_ENGINE.md) use the same typed expressions and add thresholds, sequences and actions.

## Helper reference

These helpers work in capture-time rules and in `dump -filter`.

| Helper                                         | Input and result                             | Notes                                                                       |
| ---------------------------------------------- | -------------------------------------------- | --------------------------------------------------------------------------- |
| `InSubnet(ip, cidr)`                           | Strings, returns bool                        | `InSubnet(SrcIP, "192.168.1.0/24")`                                         |
| `IsPrivateIP(ip)`, `IsPublicIP(ip)`            | String, returns bool                         | Private also covers special-use and documentation ranges, not just RFC 1918 |
| `IsApprovedWorkstation(ip)`, `InAllowlist(ip)` | String, returns bool                         | Exact match against the loaded list. An empty list always returns false.    |
| `ParsePort(port)`                              | String, returns integer                      | Converts Connection string ports                                            |
| `PortInRange(port, start, end)`                | Integers, returns bool                       | Inclusive. Use `ParsePort` first on string ports.                           |
| `TimeInRange(ts, start, end)`                  | Unix-nanosecond integers, returns bool       | Inclusive. All values must use the same unit.                               |
| `DurationSince(ts)`                            | Unix-nanosecond integer, returns nanoseconds | Uses the current clock, so it does not suit replay of old captures          |
| `FormatTime(ts, layout)`                       | Timestamp and Go layout, returns string      | Layouts use Go syntax (`2006-01-02`), not strftime                          |
| `HourOfDay(ts)`, `Weekday(ts)`                 | Timestamp, returns local hour / weekday      | Local timezone. Sunday is 0.                                                |
| `IsBusinessHours(ts, start, end)`              | Timestamp and hours, returns bool            | Monday to Friday, `[start,end)`, local timezone. Set `TZ=UTC` for UTC.      |
| `ContainsAny(text, parts...)`                  | String and strings, returns bool             | Literal substring match                                                     |
| `MatchesPattern(text, pattern)`                | Strings, returns bool                        | Regular expression. Use `(?i)` to ignore case.                              |
| `DNSResolutionMatches(...)`                    | Six typed arguments, returns bool            | DNS context helper for capture-time rules                                   |

Filter on nested lists with expr syntax, for example DNS questions for a domain:

```
len(Questions) > 0 && any(Questions, {.Name == "example.com"})
```

Check that nested data exists before you read it. CSV columns are flattened, so a CSV column name is not always a field you can use in an expression. Check the actual schema.

## Capture-time filter

`capture -filter` only filters TCP records. If the expression fails to compile, capture continues with a warning, and if evaluating it fails, the record passes through. Don't use it to drop data or to minimise what is stored. Keep the capture and run `dump -filter` on a record file instead.

## Share filtered results

When you share an export, include the input hash, the command, the expression, the Netcap version and the output hash. A filtered set of records is not a filtered packet capture. If the recipient needs the original packets, use [packet evidence](evidence.md), which also records which packets were selected.
