# Live capture

List visible interfaces before selecting one:

```sh
net util -interfaces
net capture -iface en0 -out live-audit -dpi=false -http 127.0.0.1:8080
```

`en0` is an example, not a portable interface name. Live capture needs the
platform driver and sufficient permissions. Unfiltered offline analysis does
not require those same live-capture privileges.

| Platform | Capture boundary |
| --- | --- |
| Linux | libpcap or supported packet-socket path; interface/network namespace and capabilities matter |
| macOS | BPF device permissions; seeing a local interface does not imply switch-wide visibility |
| Windows | Compatible Npcap for live capture/enumeration and BPF-dependent workflows |

Promiscuous mode cannot create SPAN/TAP traffic that never reaches the interface.
Choose the observation point with network owners; record interface/VLAN, clock,
snaplen, BPF and expected traffic before interpreting absence.

## Run and stop

Use a new output directory, monitor health and stop with Ctrl-C so finalization
can flush streams and aggregates. Killing the process can leave partial files
and unfinalized scope. `-http` explicitly keeps the UI available; bind it to
loopback under the [local hosting model](web-interface.md#hosting-boundary).

The default live snaplen is 1,514 bytes in this release; larger frames can be
truncated unless configured appropriately. Watch application admission/drop
counters separately from kernel statistics. Unavailable kernel measurements are
not zero drops. Test live loss separately from offline replay throughput.

For remote sensors, use [distributed collection](distributed-collection.md).
For packet-preserving subsets, use [evidence export](evidence.md).
