# Live capture

List the interfaces Netcap can see, then capture from one of them:

```sh
net util -interfaces
net capture -iface en0 -out live-audit -dpi=false -http 127.0.0.1:8080
```

`en0` is the usual Wi-Fi or Ethernet interface on a Mac. On Linux it is often `eth0` or `enp3s0`; use the name `net util -interfaces` prints. Live capture needs the platform capture driver and enough privileges to open the interface. Reading a PCAP file does not.

| Platform | Requirements                                                               |
| -------- | -------------------------------------------------------------------------- |
| Linux    | libpcap or a packet socket. Run as root or grant the capture capabilities. |
| macOS    | Read access to the BPF devices (`/dev/bpf*`).                              |
| Windows  | A compatible Npcap install for live capture and interface listing.         |

You only see traffic that reaches the interface. On a switched network that means your own traffic and broadcasts unless the port is a SPAN/mirror port or a TAP, and promiscuous mode does not change that. Before you conclude that something is missing, note the interface, VLAN, snaplen, BPF filter and clock of the capture host.

## Run and stop

Write to a new output directory and stop with Ctrl-C so Netcap can flush streams and aggregates. Killing the process leaves partial files. `-http` keeps the web interface running while you capture. Bind it to loopback, as described under [hosting](web-interface.md#hosting-boundary).

The default snaplen is 1,514 bytes, so larger frames (jumbo frames, or offloaded segments on some NICs) are truncated unless you raise `-snaplen`. Watch Netcap's own admission and drop counters and the kernel's statistics separately. If the kernel does not report drops, that is not the same as zero drops. Test a live capture's loss rate on your own link. Replaying a file tells you nothing about it.

To collect from remote sensors, see [distributed collection](distributed-collection.md). To save a packet-preserving subset, see [evidence export](evidence.md).
