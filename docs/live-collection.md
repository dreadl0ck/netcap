---
description: Capture from a network interface
---

# Live Collection

To capture packets live, simple use the **-iface** flag:

```text
$ net capture -iface en0
```

Use the **-interfaces** flag to list all available intefaces and their MTUs:

```text
$ net capture -interfaces
┌───────┬─────────┬───────────────────────────┬───────────────────┬───────┐
│ Index │  Name   │           Flags           │   HardwareAddr    │  MTU  │
├───────┼─────────┼───────────────────────────┼───────────────────┼───────┤
│ 1     │ lo0     │ up|loopback|multicast     │                   │ 16384 │
│ 2     │ gif0    │ pointtopoint|multicast    │                   │ 1280  │
│ 3     │ stf0    │ 0                         │                   │ 1280  │
│ 4     │ en5     │ up|broadcast|multicast    │ XX:XX:XX:XX:XX:XX │ 1500  │
│ 5     │ ap1     │ broadcast|multicast       │ XX:XX:XX:XX:XX:XX │ 1500  │
│ 6     │ en0     │ up|broadcast|multicast    │ XX:XX:XX:XX:XX:XX │ 1500  │
│ 7     │ en4     │ up|broadcast|multicast    │ XX:XX:XX:XX:XX:XX │ 1500  │
│ 8     │ en1     │ up|broadcast|multicast    │ XX:XX:XX:XX:XX:XX │ 1500  │
│ 9     │ en2     │ up|broadcast|multicast    │ XX:XX:XX:XX:XX:XX │ 1500  │
│ 10    │ en3     │ up|broadcast|multicast    │ XX:XX:XX:XX:XX:XX │ 1500  │
│ 11    │ bridge0 │ up|broadcast|multicast    │ XX:XX:XX:XX:XX:XX │ 1500  │
│ 12    │ p2p0    │ up|broadcast|multicast    │ XX:XX:XX:XX:XX:XX │ 2304  │
│ 13    │ awdl0   │ up|broadcast|multicast    │ XX:XX:XX:XX:XX:XX │ 1484  │
│ 14    │ llw0    │ up|broadcast|multicast    │ XX:XX:XX:XX:XX:XX │ 1500  │
│ 15    │ utun0   │ up|pointtopoint|multicast │                   │ 1380  │
│ 16    │ utun1   │ up|pointtopoint|multicast │                   │ 2000  │
│ 17    │ utun2   │ up|pointtopoint|multicast │                   │ 1380  │
│ 18    │ utun3   │ up|pointtopoint|multicast │                   │ 1380  │
│ 19    │ utun4   │ up|pointtopoint|multicast │                   │ 1380  │
│ 20    │ utun5   │ up|pointtopoint|multicast │                   │ 1380  │
│ 21    │ utun6   │ up|pointtopoint|multicast │                   │ 1380  │
│ 22    │ utun7   │ up|pointtopoint|multicast │                   │ 1380  │
└───────┴─────────┴───────────────────────────┴───────────────────┴───────┘
```

Netcap uses promiscous mode by default. You can toggle this behavior with the **-promisc** flag:

```text
$ net capture -iface en0 -promisc=false
```

## Windows

For windows, things work a little bit different.

First, download & install the latest version of **WinPcap**:

{% embed url="https://www.winpcap.org/install/" %}

Next, open a CMD prompt and run:

```aspnet
C:\>getmac /fo csv /v
"Connection Name","Network Adapter","Physical Address","Transport Name"
"Ethernet0","Intel(R) PRO/1000 MT Network Connection","00-0C-29-BB-EC-9B","\Device\Tcpip_{B1B1E59F-FA8F-4A7B-B28C-7A26F6E00F5A}"
```

Note down the Identifier for your adapter of interest \(here: **Ethernet0**\), in this example the identifier is:

```aspnet
\Device\Tcpip_{B1B1E59F-FA8F-4A7B-B28C-7A26F6E00F5A}
```

To capture traffic on the interface, you must prefix the **ID \({B1B1E59F-FA8F-4A7B-B28C-7A26F6E00F5A}\)** with **\Device\NPF\_**

```aspnet
net.exe capture -iface \Device\NPF_{B1B1E59F-FA8F-4A7B-B28C-7A26F6E00F5A}
```

