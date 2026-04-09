# eBPF Integration for Netcap

This document outlines potential integration opportunities between Netcap and the [cilium/ebpf](https://github.com/cilium/ebpf) library for enhanced performance and capabilities on Linux systems.

## Table of Contents

- [Executive Summary](#executive-summary)
- [Current Architecture](#current-architecture)
- [eBPF Overview](#ebpf-overview)
- [Integration Opportunities](#integration-opportunities)
  - [1. XDP-Based Packet Capture](#1-xdp-based-packet-capture)
  - [2. Kernel-Space Flow Tracking](#2-kernel-space-flow-tracking)
  - [3. eBPF Firewall Module](#3-ebpf-firewall-module)
  - [4. Kernel-Space Protocol Detection](#4-kernel-space-protocol-detection)
  - [5. Real-Time Kernel Metrics](#5-real-time-kernel-metrics)
  - [6. TCP Stream Sampling](#6-tcp-stream-sampling)
- [Proposed Architecture](#proposed-architecture)
- [Implementation Plan](#implementation-plan)
- [Technical Requirements](#technical-requirements)
- [Performance Comparison](#performance-comparison)
- [Limitations and Considerations](#limitations-and-considerations)
- [References](#references)

---

## Executive Summary

eBPF (extended Berkeley Packet Filter) is a revolutionary Linux kernel technology that allows running sandboxed programs in kernel space without modifying the kernel or loading kernel modules. By integrating cilium/ebpf into Netcap, we can achieve:

- **10-100x faster packet filtering** via XDP (eXpress Data Path)
- **Zero-copy packet delivery** from kernel to userspace
- **Sub-microsecond firewall blocking** replacing iptables
- **Lock-free per-CPU metrics** for high-throughput statistics
- **Kernel-level flow aggregation** reducing userspace load

This integration would position Netcap as a high-performance network analysis framework capable of handling 10Gbps+ traffic on commodity hardware.

---

## Current Architecture

### Packet Capture

| Platform | Method | Library |
|----------|--------|---------|
| Linux | Raw AF_PACKET sockets | `gopacket/pcapgo` |
| macOS/Windows | libpcap C bindings | `gopacket/pcap` |

**Current flow (Linux)**:
```
NIC → Kernel Network Stack → AF_PACKET Socket → Userspace → Netcap
```

### BPF Filtering

Netcap uses classical BPF (cBPF) filters applied via:
- `handle.SetBPFFilter(bpf)` for libpcap
- `handle.SetBPF(rawBPF(bpf))` for pcapgo

### Flow Tracking

Connection tracking happens entirely in userspace:
- `collector/worker.go` - Symmetric flow hashing for worker distribution
- `reassembly/` - TCP stream reassembly
- DPI flow tracking via go-dpi's `FlowTrackerInstance`

### Firewall Integration

The `firewall/` package uses `coreos/go-iptables` for:
- Creating custom iptables chains
- Adding/removing block rules
- IPv4 and IPv6 support
- Automatic rule expiration

### Metrics Collection

Prometheus metrics in `collector/metrics.go`:
- Protocol counters (atomic operations)
- Decoder timing gauges
- Packets per second

---

## eBPF Overview

### What is eBPF?

eBPF is an in-kernel virtual machine that runs sandboxed programs at various hook points in the Linux kernel. Key features:

- **Safety**: Programs are verified before loading
- **Performance**: JIT-compiled to native code
- **Flexibility**: Can be attached to many kernel hook points
- **Observability**: Access to kernel data structures

### cilium/ebpf Library

[cilium/ebpf](https://github.com/cilium/ebpf) is a pure-Go library providing:

- Loading and managing eBPF programs
- Interacting with eBPF maps
- Attaching programs to various hooks (XDP, TC, kprobes, etc.)
- Code generation via `bpf2go`

```go
import (
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
)
```

### eBPF Program Types Relevant to Netcap

| Type | Hook Point | Use Case |
|------|------------|----------|
| `BPF_PROG_TYPE_XDP` | NIC driver | Ultra-fast packet filtering |
| `BPF_PROG_TYPE_SCHED_CLS` | TC ingress/egress | Traffic classification |
| `BPF_PROG_TYPE_SOCKET_FILTER` | Socket | Per-socket filtering |
| `BPF_PROG_TYPE_CGROUP_SKB` | cgroup | Container traffic control |

### eBPF Map Types Relevant to Netcap

| Type | Use Case |
|------|----------|
| `BPF_MAP_TYPE_HASH` | Flow tracking, connection state |
| `BPF_MAP_TYPE_LPM_TRIE` | CIDR-based IP blocking |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | Lock-free per-CPU counters |
| `BPF_MAP_TYPE_RINGBUF` | Efficient kernel→userspace data transfer |
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | Per-CPU event buffers |

---

## Integration Opportunities

### 1. XDP-Based Packet Capture

#### Current State

Linux live capture uses AF_PACKET sockets via `pcapgo.NewEthernetHandle()`:

```go
// collector/live_linux.go
handle, err := pcapgo.NewEthernetHandle(i)
data, ci, err = handle.ReadPacketData()
```

This involves:
- Kernel network stack processing
- Memory copies between kernel and userspace
- Socket buffer management overhead

#### eBPF Solution

XDP programs run at the earliest possible point in the network stack—directly in the NIC driver or immediately after:

```
NIC → XDP Program → Ring Buffer → Userspace → Netcap
         ↓
    (packets can be
     dropped/modified
     before kernel stack)
```

**BPF Program (`bpf/xdp_capture.c`)**:

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Ring buffer for sending packets to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 * 1024);  // 256 MB
} events SEC(".maps");

// Packet metadata sent to userspace
struct packet_event {
    __u64 timestamp;
    __u32 len;
    __u32 caplen;
    __u16 ifindex;
    __u8 data[1500];  // Configurable snap length
};

// Filter map - allows dynamic filtering configuration
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // Filter ID
    __type(value, __u64);  // Filter config
} filters SEC(".maps");

SEC("xdp")
int xdp_capture(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Bounds check
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;
    
    struct ethhdr *eth = data;
    
    // Optional: Apply filters here
    // - Protocol filtering
    // - IP/port filtering
    // - Rate limiting
    
    // Calculate packet length
    __u32 pkt_len = data_end - data;
    __u32 caplen = pkt_len;
    if (caplen > sizeof(((struct packet_event *)0)->data))
        caplen = sizeof(((struct packet_event *)0)->data);
    
    // Reserve space in ring buffer
    struct packet_event *e = bpf_ringbuf_reserve(&events, 
        sizeof(*e) - sizeof(e->data) + caplen, 0);
    if (!e)
        return XDP_PASS;
    
    // Fill metadata
    e->timestamp = bpf_ktime_get_ns();
    e->len = pkt_len;
    e->caplen = caplen;
    e->ifindex = ctx->ingress_ifindex;
    
    // Copy packet data
    if (bpf_xdp_load_bytes(ctx, 0, e->data, caplen) < 0) {
        bpf_ringbuf_discard(e, 0);
        return XDP_PASS;
    }
    
    bpf_ringbuf_submit(e, 0);
    
    return XDP_PASS;  // Continue normal processing
}

char LICENSE[] SEC("license") = "GPL";
```

**Go Integration (`collector/live_linux_xdp.go`)**:

```go
//go:build linux

package collector

import (
    "context"
    "encoding/binary"
    "fmt"
    "net"
    "time"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/gopacket/gopacket"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 xdpCapture ./bpf/xdp_capture.c

// packetEvent mirrors the C struct
type packetEvent struct {
    Timestamp uint64
    Len       uint32
    CapLen    uint32
    IfIndex   uint16
    _         [2]byte // padding
    Data      []byte
}

// CollectLiveXDP starts high-performance packet capture using XDP.
func (c *Collector) CollectLiveXDP(iface string, ctx context.Context) error {
    defer c.recoverFromPanic()

    // Get interface index
    netIface, err := net.InterfaceByName(iface)
    if err != nil {
        return fmt.Errorf("failed to get interface %s: %w", iface, err)
    }

    // Load pre-compiled eBPF objects
    objs := xdpCaptureObjects{}
    if err := loadXdpCaptureObjects(&objs, nil); err != nil {
        return fmt.Errorf("failed to load eBPF objects: %w", err)
    }
    defer objs.Close()

    // Attach XDP program to interface
    xdpLink, err := link.AttachXDP(link.XDPOptions{
        Program:   objs.XdpCapture,
        Interface: netIface.Index,
        Flags:     link.XDPGenericMode, // Use driver mode if available
    })
    if err != nil {
        return fmt.Errorf("failed to attach XDP program: %w", err)
    }
    defer xdpLink.Close()

    // Create ring buffer reader
    rd, err := ringbuf.NewReader(objs.Events)
    if err != nil {
        return fmt.Errorf("failed to create ring buffer reader: %w", err)
    }
    defer rd.Close()

    // Initialize collector
    if err := c.Init(); err != nil {
        return err
    }

    stopProgress := c.printProgressInterval()
    stopPeriodicFlush := c.startPeriodicFlush()

    c.mu.Lock()
    c.isLive = true
    c.mu.Unlock()

    // Read packets from ring buffer
    for {
        select {
        case <-ctx.Done():
            fmt.Println("XDP capture canceled via context")
            goto done
        default:
            record, err := rd.Read()
            if err != nil {
                if err == ringbuf.ErrClosed {
                    goto done
                }
                continue
            }

            // Parse packet event
            event := parsePacketEvent(record.RawSample)
            
            // Create capture info
            ci := gopacket.CaptureInfo{
                Timestamp:     time.Unix(0, int64(event.Timestamp)),
                CaptureLength: int(event.CapLen),
                Length:        int(event.Len),
            }

            c.statMutex.Lock()
            c.wg.Add(1)
            c.statMutex.Unlock()

            c.handleRawPacketData(event.Data, &ci)
        }
    }

done:
    stopProgress <- struct{}{}
    close(stopPeriodicFlush)
    c.cleanup(false)

    return nil
}

func parsePacketEvent(data []byte) *packetEvent {
    event := &packetEvent{
        Timestamp: binary.LittleEndian.Uint64(data[0:8]),
        Len:       binary.LittleEndian.Uint32(data[8:12]),
        CapLen:    binary.LittleEndian.Uint32(data[12:16]),
        IfIndex:   binary.LittleEndian.Uint16(data[16:18]),
    }
    event.Data = data[20 : 20+event.CapLen]
    return event
}
```

#### Benefits

| Aspect | AF_PACKET | XDP |
|--------|-----------|-----|
| Latency | ~10-50μs | ~1-5μs |
| Throughput | ~1-5 Mpps | ~10-50 Mpps |
| CPU usage | High | Low |
| Kernel bypass | No | Partial |
| Zero-copy | No | Yes (ring buffer) |

---

### 2. Kernel-Space Flow Tracking

#### Current State

Flow tracking happens in userspace with:
- `collector/worker.go` - Symmetric flow hashing
- `reassembly/connection.go` - TCP connection tracking
- DPI's internal flow tracker

#### eBPF Solution

Maintain flow state in kernel BPF maps:

**BPF Program (`bpf/flow_tracker.c`)**:

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Flow key - symmetric by design
struct flow_key {
    __u32 ip_lo;      // Lower IP (for symmetry)
    __u32 ip_hi;      // Higher IP
    __u16 port_lo;    // Lower port
    __u16 port_hi;    // Higher port
    __u8 protocol;    // L4 protocol
    __u8 ip_version;  // 4 or 6
    __u16 _pad;
};

// Flow statistics
struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u32 tcp_flags;      // Accumulated TCP flags
    __u16 src_port_orig;  // Original source port (for direction)
    __u8 state;           // Connection state
    __u8 _pad;
};

// Flow map - holds up to 1M concurrent flows
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} flows SEC(".maps");

// New flow events - notify userspace of new connections
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} new_flows SEC(".maps");

struct new_flow_event {
    struct flow_key key;
    __u64 timestamp;
};

// Helper to create symmetric flow key
static __always_inline void make_flow_key(
    struct flow_key *key,
    __u32 saddr, __u32 daddr,
    __u16 sport, __u16 dport,
    __u8 proto)
{
    key->protocol = proto;
    key->ip_version = 4;
    
    // Ensure symmetric key regardless of direction
    if (saddr < daddr || (saddr == daddr && sport < dport)) {
        key->ip_lo = saddr;
        key->ip_hi = daddr;
        key->port_lo = sport;
        key->port_hi = dport;
    } else {
        key->ip_lo = daddr;
        key->ip_hi = saddr;
        key->port_lo = dport;
        key->port_hi = sport;
    }
}

SEC("tc")
int track_flows(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    // Only handle IPv4 for now
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    // Parse IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    __u16 sport = 0, dport = 0;
    __u32 tcp_flags = 0;
    
    // Parse transport layer
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
        tcp_flags = (tcp->fin) | (tcp->syn << 1) | 
                    (tcp->rst << 2) | (tcp->psh << 3) |
                    (tcp->ack << 4) | (tcp->urg << 5);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
    } else {
        return TC_ACT_OK;
    }
    
    // Create flow key
    struct flow_key key = {};
    make_flow_key(&key, ip->saddr, ip->daddr, sport, dport, ip->protocol);
    
    // Lookup or create flow entry
    struct flow_stats *stats = bpf_map_lookup_elem(&flows, &key);
    __u64 now = bpf_ktime_get_ns();
    
    if (stats) {
        // Update existing flow
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, skb->len);
        stats->last_seen_ns = now;
        stats->tcp_flags |= tcp_flags;
    } else {
        // New flow
        struct flow_stats new_stats = {
            .packets = 1,
            .bytes = skb->len,
            .first_seen_ns = now,
            .last_seen_ns = now,
            .tcp_flags = tcp_flags,
            .src_port_orig = sport,
            .state = 0,
        };
        
        bpf_map_update_elem(&flows, &key, &new_stats, BPF_ANY);
        
        // Notify userspace of new flow
        struct new_flow_event *event = bpf_ringbuf_reserve(
            &new_flows, sizeof(*event), 0);
        if (event) {
            event->key = key;
            event->timestamp = now;
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
```

**Go Integration (`collector/flow_tracker_ebpf.go`)**:

```go
//go:build linux

package collector

import (
    "encoding/binary"
    "net"
    "sync"
    "time"

    "github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 flowTracker ./bpf/flow_tracker.c

// FlowKey represents a bidirectional flow
type FlowKey struct {
    IPLo      uint32
    IPHi      uint32
    PortLo    uint16
    PortHi    uint16
    Protocol  uint8
    IPVersion uint8
}

// FlowStats holds per-flow statistics
type FlowStats struct {
    Packets     uint64
    Bytes       uint64
    FirstSeenNs uint64
    LastSeenNs  uint64
    TCPFlags    uint32
    SrcPortOrig uint16
    State       uint8
}

// EBPFFlowTracker provides kernel-accelerated flow tracking
type EBPFFlowTracker struct {
    objs     *flowTrackerObjects
    tcLink   interface{ Close() error }
    flowsMap *ebpf.Map
    mu       sync.RWMutex
}

// NewEBPFFlowTracker creates a new eBPF-based flow tracker
func NewEBPFFlowTracker(iface string) (*EBPFFlowTracker, error) {
    objs := flowTrackerObjects{}
    if err := loadFlowTrackerObjects(&objs, nil); err != nil {
        return nil, err
    }

    // Attach TC program (implementation details omitted)
    
    return &EBPFFlowTracker{
        objs:     &objs,
        flowsMap: objs.Flows,
    }, nil
}

// GetFlowStats returns all current flow statistics
func (t *EBPFFlowTracker) GetFlowStats() ([]FlowInfo, error) {
    t.mu.RLock()
    defer t.mu.RUnlock()

    var flows []FlowInfo
    
    var key FlowKey
    var stats FlowStats
    
    iter := t.flowsMap.Iterate()
    for iter.Next(&key, &stats) {
        flows = append(flows, FlowInfo{
            SrcIP:     intToIP(key.IPLo),
            DstIP:     intToIP(key.IPHi),
            SrcPort:   key.PortLo,
            DstPort:   key.PortHi,
            Protocol:  key.Protocol,
            Packets:   stats.Packets,
            Bytes:     stats.Bytes,
            FirstSeen: time.Unix(0, int64(stats.FirstSeenNs)),
            LastSeen:  time.Unix(0, int64(stats.LastSeenNs)),
        })
    }
    
    return flows, iter.Err()
}

// GetFlowCount returns the number of active flows
func (t *EBPFFlowTracker) GetFlowCount() (int, error) {
    var count int
    var key FlowKey
    
    iter := t.flowsMap.Iterate()
    for iter.Next(&key, nil) {
        count++
    }
    
    return count, iter.Err()
}

func intToIP(i uint32) net.IP {
    ip := make(net.IP, 4)
    binary.LittleEndian.PutUint32(ip, i)
    return ip
}
```

#### Benefits

- **Scalability**: Track millions of flows with minimal userspace overhead
- **Accuracy**: Kernel updates are atomic and consistent
- **Persistence**: Flow state survives userspace restarts
- **Performance**: No per-packet userspace processing for flow updates

---

### 3. eBPF Firewall Module

#### Current State

The `firewall/manager.go` uses iptables:

```go
// Current implementation
func (m *Manager) BlockIP(ip string, config *BlockConfig) error {
    // Uses iptables.Append() - spawns iptables process
    return ipt.Append("filter", m.chainName, ruleSpec...)
}
```

Issues:
- Each rule change spawns a new `iptables` process
- Linear rule matching in kernel
- Millisecond-scale latency for updates

#### eBPF Solution

Use XDP with LPM trie for O(1) lookups:

**BPF Program (`bpf/firewall.c`)**:

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// LPM trie for IPv4 CIDR blocking
struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct block_value {
    __u64 blocked_at;
    __u64 expires_at;
    __u32 packets_blocked;
    __u8 action;  // 0 = drop, 1 = reject
    __u8 _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct block_value);
} blocked_ips SEC(".maps");

// IPv6 blocking
struct ipv6_lpm_key {
    __u32 prefixlen;
    __u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv6_lpm_key);
    __type(value, struct block_value);
} blocked_ips6 SEC(".maps");

// Whitelist (checked before blocklist)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
} whitelist SEC(".maps");

// Statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

enum {
    STAT_PACKETS_TOTAL = 0,
    STAT_PACKETS_BLOCKED = 1,
    STAT_PACKETS_WHITELISTED = 2,
    STAT_PACKETS_PASSED = 3,
};

static __always_inline void inc_stat(__u32 key)
{
    __u64 *val = bpf_map_lookup_elem(&stats, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    inc_stat(STAT_PACKETS_TOTAL);
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    __u16 eth_proto = eth->h_proto;
    
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        
        // Check source IP against whitelist
        struct ipv4_lpm_key wl_key = {
            .prefixlen = 32,
            .addr = ip->saddr,
        };
        
        if (bpf_map_lookup_elem(&whitelist, &wl_key)) {
            inc_stat(STAT_PACKETS_WHITELISTED);
            return XDP_PASS;
        }
        
        // Check source IP against blocklist
        struct ipv4_lpm_key bl_key = {
            .prefixlen = 32,
            .addr = ip->saddr,
        };
        
        struct block_value *block = bpf_map_lookup_elem(&blocked_ips, &bl_key);
        if (block) {
            // Check expiration
            __u64 now = bpf_ktime_get_ns();
            if (block->expires_at == 0 || now < block->expires_at) {
                __sync_fetch_and_add(&block->packets_blocked, 1);
                inc_stat(STAT_PACKETS_BLOCKED);
                return XDP_DROP;
            }
        }
        
        // Also check destination IP (for egress blocking)
        bl_key.addr = ip->daddr;
        block = bpf_map_lookup_elem(&blocked_ips, &bl_key);
        if (block) {
            __u64 now = bpf_ktime_get_ns();
            if (block->expires_at == 0 || now < block->expires_at) {
                __sync_fetch_and_add(&block->packets_blocked, 1);
                inc_stat(STAT_PACKETS_BLOCKED);
                return XDP_DROP;
            }
        }
    }
    // IPv6 handling similar...
    
    inc_stat(STAT_PACKETS_PASSED);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
```

**Go Integration (`firewall/ebpf_manager.go`)**:

```go
//go:build linux

package firewall

import (
    "encoding/binary"
    "fmt"
    "net"
    "sync"
    "time"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 firewall ./bpf/firewall.c

// IPv4LPMKey for BPF LPM trie
type IPv4LPMKey struct {
    PrefixLen uint32
    Addr      uint32
}

// BlockValue stored in BPF map
type BlockValue struct {
    BlockedAt      uint64
    ExpiresAt      uint64
    PacketsBlocked uint32
    Action         uint8
    _              [3]byte
}

// EBPFManager provides XDP-based firewall functionality
type EBPFManager struct {
    objs        *firewallObjects
    xdpLink     link.Link
    blockedIPs  *ebpf.Map
    blockedIPs6 *ebpf.Map
    whitelist   *ebpf.Map
    stats       *ebpf.Map
    
    mu         sync.RWMutex
    iface      string
    verbose    bool
}

// NewEBPFManager creates a new XDP firewall manager
func NewEBPFManager(iface string, verbose bool) (*EBPFManager, error) {
    // Get interface
    netIface, err := net.InterfaceByName(iface)
    if err != nil {
        return nil, fmt.Errorf("interface %s not found: %w", iface, err)
    }

    // Load eBPF objects
    objs := firewallObjects{}
    if err := loadFirewallObjects(&objs, nil); err != nil {
        return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
    }

    // Attach XDP program
    xdpLink, err := link.AttachXDP(link.XDPOptions{
        Program:   objs.XdpFirewall,
        Interface: netIface.Index,
        Flags:     link.XDPGenericMode,
    })
    if err != nil {
        objs.Close()
        return nil, fmt.Errorf("failed to attach XDP program: %w", err)
    }

    return &EBPFManager{
        objs:        &objs,
        xdpLink:     xdpLink,
        blockedIPs:  objs.BlockedIps,
        blockedIPs6: objs.BlockedIps6,
        whitelist:   objs.Whitelist,
        stats:       objs.Stats,
        iface:       iface,
        verbose:     verbose,
    }, nil
}

// BlockIP blocks an IP address or CIDR
func (m *EBPFManager) BlockIP(ipOrCIDR string, duration time.Duration) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    ip, network, err := net.ParseCIDR(ipOrCIDR)
    if err != nil {
        // Try parsing as plain IP
        ip = net.ParseIP(ipOrCIDR)
        if ip == nil {
            return fmt.Errorf("invalid IP or CIDR: %s", ipOrCIDR)
        }
        // Create /32 or /128 network
        if ip.To4() != nil {
            _, network, _ = net.ParseCIDR(ip.String() + "/32")
        } else {
            _, network, _ = net.ParseCIDR(ip.String() + "/128")
        }
    }

    prefixLen, _ := network.Mask.Size()
    now := time.Now().UnixNano()
    
    value := BlockValue{
        BlockedAt:      uint64(now),
        PacketsBlocked: 0,
        Action:         0, // DROP
    }
    
    if duration > 0 {
        value.ExpiresAt = uint64(now + duration.Nanoseconds())
    }

    if ip.To4() != nil {
        // IPv4
        key := IPv4LPMKey{
            PrefixLen: uint32(prefixLen),
            Addr:      binary.LittleEndian.Uint32(ip.To4()),
        }
        if err := m.blockedIPs.Put(key, value); err != nil {
            return fmt.Errorf("failed to add block rule: %w", err)
        }
    } else {
        // IPv6 - similar implementation
    }

    if m.verbose {
        fmt.Printf("[EBPF-FW] Blocked %s (expires: %v)\n", 
            ipOrCIDR, time.Unix(0, int64(value.ExpiresAt)))
    }

    return nil
}

// UnblockIP removes a block
func (m *EBPFManager) UnblockIP(ipOrCIDR string) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    ip, network, err := net.ParseCIDR(ipOrCIDR)
    if err != nil {
        ip = net.ParseIP(ipOrCIDR)
        if ip == nil {
            return fmt.Errorf("invalid IP or CIDR: %s", ipOrCIDR)
        }
        if ip.To4() != nil {
            _, network, _ = net.ParseCIDR(ip.String() + "/32")
        } else {
            _, network, _ = net.ParseCIDR(ip.String() + "/128")
        }
    }

    prefixLen, _ := network.Mask.Size()

    if ip.To4() != nil {
        key := IPv4LPMKey{
            PrefixLen: uint32(prefixLen),
            Addr:      binary.LittleEndian.Uint32(ip.To4()),
        }
        if err := m.blockedIPs.Delete(key); err != nil {
            return fmt.Errorf("failed to remove block rule: %w", err)
        }
    }

    return nil
}

// GetStats returns firewall statistics
func (m *EBPFManager) GetStats() (map[string]uint64, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()

    stats := make(map[string]uint64)
    statNames := []string{"packets_total", "packets_blocked", 
                          "packets_whitelisted", "packets_passed"}

    for i, name := range statNames {
        var values []uint64
        key := uint32(i)
        if err := m.stats.Lookup(key, &values); err == nil {
            var total uint64
            for _, v := range values {
                total += v
            }
            stats[name] = total
        }
    }

    return stats, nil
}

// Close cleans up XDP program and maps
func (m *EBPFManager) Close() error {
    m.mu.Lock()
    defer m.mu.Unlock()

    if m.xdpLink != nil {
        m.xdpLink.Close()
    }
    if m.objs != nil {
        m.objs.Close()
    }

    return nil
}
```

#### Performance Comparison

| Operation | iptables | eBPF XDP |
|-----------|----------|----------|
| Add rule | ~5-50ms | ~1-10μs |
| Lookup | O(n) rules | O(1) LPM |
| Throughput | ~1M pps | ~10M+ pps |
| Memory | Variable | Fixed map size |
| Atomicity | Requires lock | Lock-free |

---

### 4. Kernel-Space Protocol Detection

#### Current State

Deep Packet Inspection in `dpi/dpi.go`:
- nDPI (C library)
- libprotoident (C library)
- go-dpi classifiers (Go)

All run in userspace after packet capture.

#### eBPF Solution

Implement simple protocol signatures in kernel for fast pre-filtering:

**BPF Program (`bpf/protocol_detect.c`)**:

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Protocol IDs
enum {
    PROTO_UNKNOWN = 0,
    PROTO_HTTP = 1,
    PROTO_HTTPS = 2,
    PROTO_DNS = 3,
    PROTO_SSH = 4,
    PROTO_SMTP = 5,
    PROTO_FTP = 6,
    PROTO_IMAP = 7,
    PROTO_POP3 = 8,
};

// Per-flow protocol cache
struct flow_proto {
    __u8 protocol;
    __u8 confidence;  // 0-100
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct flow_key);
    __type(value, struct flow_proto);
} protocol_cache SEC(".maps");

// Protocol statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} protocol_stats SEC(".maps");

// Simple pattern matching helpers
static __always_inline int starts_with(void *data, void *data_end, 
                                        const char *pattern, int len)
{
    if (data + len > data_end)
        return 0;
    
    for (int i = 0; i < len; i++) {
        if (((char *)data)[i] != pattern[i])
            return 0;
    }
    return 1;
}

// Detect HTTP
static __always_inline __u8 detect_http(void *payload, void *data_end)
{
    // HTTP methods
    if (starts_with(payload, data_end, "GET ", 4) ||
        starts_with(payload, data_end, "POST", 4) ||
        starts_with(payload, data_end, "PUT ", 4) ||
        starts_with(payload, data_end, "HEAD", 4) ||
        starts_with(payload, data_end, "HTTP", 4) ||
        starts_with(payload, data_end, "DELE", 4) ||
        starts_with(payload, data_end, "OPTI", 4) ||
        starts_with(payload, data_end, "PATC", 4)) {
        return PROTO_HTTP;
    }
    return PROTO_UNKNOWN;
}

// Detect TLS
static __always_inline __u8 detect_tls(void *payload, void *data_end)
{
    if (payload + 3 > data_end)
        return PROTO_UNKNOWN;
    
    __u8 *p = payload;
    
    // TLS handshake: 0x16 0x03 0x0X
    if (p[0] == 0x16 && p[1] == 0x03 && (p[2] >= 0x00 && p[2] <= 0x04)) {
        return PROTO_HTTPS;
    }
    
    return PROTO_UNKNOWN;
}

// Detect SSH
static __always_inline __u8 detect_ssh(void *payload, void *data_end)
{
    if (starts_with(payload, data_end, "SSH-", 4)) {
        return PROTO_SSH;
    }
    return PROTO_UNKNOWN;
}

// Detect DNS
static __always_inline __u8 detect_dns(__u16 sport, __u16 dport, 
                                        void *payload, void *data_end)
{
    // DNS typically on port 53
    if (sport == 53 || dport == 53) {
        // Basic DNS header validation
        if (payload + 12 > data_end)
            return PROTO_UNKNOWN;
        
        // Check for valid DNS flags
        __u8 *p = payload;
        __u16 flags = (p[2] << 8) | p[3];
        __u16 qdcount = (p[4] << 8) | p[5];
        
        if (qdcount > 0 && qdcount < 100) {
            return PROTO_DNS;
        }
    }
    return PROTO_UNKNOWN;
}

SEC("tc")
int detect_protocol(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Parse headers...
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    void *payload = NULL;
    __u16 sport = 0, dport = 0;
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
        payload = (void *)tcp + (tcp->doff * 4);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
        payload = (void *)(udp + 1);
    } else {
        return TC_ACT_OK;
    }
    
    if (payload >= data_end)
        return TC_ACT_OK;
    
    // Try protocol detection
    __u8 proto = PROTO_UNKNOWN;
    
    if (ip->protocol == IPPROTO_TCP) {
        // Check well-known ports first
        if (dport == 80 || sport == 80 || dport == 8080 || sport == 8080) {
            proto = detect_http(payload, data_end);
        } else if (dport == 443 || sport == 443) {
            proto = detect_tls(payload, data_end);
        } else if (dport == 22 || sport == 22) {
            proto = detect_ssh(payload, data_end);
        }
        
        // Fallback: try all detectors
        if (proto == PROTO_UNKNOWN) {
            proto = detect_http(payload, data_end);
            if (proto == PROTO_UNKNOWN)
                proto = detect_tls(payload, data_end);
            if (proto == PROTO_UNKNOWN)
                proto = detect_ssh(payload, data_end);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        proto = detect_dns(sport, dport, payload, data_end);
    }
    
    // Update statistics
    if (proto != PROTO_UNKNOWN) {
        __u32 key = proto;
        __u64 *val = bpf_map_lookup_elem(&protocol_stats, &key);
        if (val)
            __sync_fetch_and_add(val, 1);
    }
    
    // Cache result for flow
    // (flow key creation and caching code...)
    
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
```

#### Benefits

- **Pre-filtering**: Only pass relevant packets to full DPI
- **Fast path**: Common protocols identified at line rate
- **Offload**: Reduce userspace CPU usage
- **Stats**: Per-protocol packet counts without userspace overhead

---

### 5. Real-Time Kernel Metrics

#### Current State

Prometheus metrics in `collector/metrics.go`:

```go
var allProtosTotal = prometheus.NewCounterVec(...)
var unknownProtosTotal = prometheus.NewCounterVec(...)
var decodingErrorsTotal = prometheus.NewCounterVec(...)
```

Updated with atomic operations from userspace.

#### eBPF Solution

Use per-CPU arrays for lock-free counters:

**BPF Program (`bpf/metrics.c`)**:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Metric indices
enum {
    METRIC_PACKETS = 0,
    METRIC_BYTES = 1,
    METRIC_TCP = 2,
    METRIC_UDP = 3,
    METRIC_ICMP = 4,
    METRIC_OTHER = 5,
    METRIC_ERRORS = 6,
    METRIC_DROPPED = 7,
    METRIC_MAX = 32,
};

// Per-CPU counters - no locks needed
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, METRIC_MAX);
    __type(key, __u32);
    __type(value, __u64);
} metrics SEC(".maps");

// Per-protocol counters (256 protocols max)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} protocol_metrics SEC(".maps");

// Histogram buckets for packet sizes
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);  // Buckets: 0-63, 64-127, ..., 8192+
    __type(key, __u32);
    __type(value, __u64);
} size_histogram SEC(".maps");

static __always_inline void inc_metric(__u32 key)
{
    __u64 *val = bpf_map_lookup_elem(&metrics, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline void add_metric(__u32 key, __u64 delta)
{
    __u64 *val = bpf_map_lookup_elem(&metrics, &key);
    if (val)
        __sync_fetch_and_add(val, delta);
}

static __always_inline void record_packet_size(__u32 len)
{
    // Log2-based bucketing
    __u32 bucket = 0;
    if (len >= 64) bucket = 1;
    if (len >= 128) bucket = 2;
    if (len >= 256) bucket = 3;
    if (len >= 512) bucket = 4;
    if (len >= 1024) bucket = 5;
    if (len >= 1500) bucket = 6;
    if (len >= 2048) bucket = 7;
    if (len >= 4096) bucket = 8;
    if (len >= 8192) bucket = 9;
    
    __u64 *val = bpf_map_lookup_elem(&size_histogram, &bucket);
    if (val)
        __sync_fetch_and_add(val, 1);
}

SEC("xdp")
int collect_metrics(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    __u32 len = data_end - data;
    
    // Count packets and bytes
    inc_metric(METRIC_PACKETS);
    add_metric(METRIC_BYTES, len);
    
    // Record size histogram
    record_packet_size(len);
    
    // Parse and count by protocol
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        
        switch (ip->protocol) {
        case IPPROTO_TCP:
            inc_metric(METRIC_TCP);
            break;
        case IPPROTO_UDP:
            inc_metric(METRIC_UDP);
            break;
        case IPPROTO_ICMP:
            inc_metric(METRIC_ICMP);
            break;
        default:
            inc_metric(METRIC_OTHER);
        }
        
        // Count by IP protocol number
        __u32 proto_key = ip->protocol;
        __u64 *proto_val = bpf_map_lookup_elem(&protocol_metrics, &proto_key);
        if (proto_val)
            __sync_fetch_and_add(proto_val, 1);
    }
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
```

**Go Integration (`collector/metrics_ebpf.go`)**:

```go
//go:build linux

package collector

import (
    "github.com/cilium/ebpf"
    "github.com/prometheus/client_golang/prometheus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 metrics ./bpf/metrics.c

// EBPFMetrics provides kernel-accelerated metrics collection
type EBPFMetrics struct {
    objs             *metricsObjects
    metricsMap       *ebpf.Map
    protocolMap      *ebpf.Map
    sizeHistogramMap *ebpf.Map
}

// Metric keys
const (
    metricPackets = 0
    metricBytes   = 1
    metricTCP     = 2
    metricUDP     = 3
    metricICMP    = 4
    metricOther   = 5
)

// GetMetrics reads all metrics from kernel
func (m *EBPFMetrics) GetMetrics() map[string]uint64 {
    result := make(map[string]uint64)
    
    names := map[uint32]string{
        metricPackets: "packets_total",
        metricBytes:   "bytes_total",
        metricTCP:     "tcp_packets",
        metricUDP:     "udp_packets",
        metricICMP:    "icmp_packets",
        metricOther:   "other_packets",
    }
    
    for key, name := range names {
        var perCPUValues []uint64
        if err := m.metricsMap.Lookup(key, &perCPUValues); err == nil {
            var total uint64
            for _, v := range perCPUValues {
                total += v
            }
            result[name] = total
        }
    }
    
    return result
}

// RegisterPrometheusCollector creates a Prometheus collector
func (m *EBPFMetrics) RegisterPrometheusCollector() {
    collector := &ebpfPrometheusCollector{metrics: m}
    prometheus.MustRegister(collector)
}

type ebpfPrometheusCollector struct {
    metrics *EBPFMetrics
}

func (c *ebpfPrometheusCollector) Describe(ch chan<- *prometheus.Desc) {
    ch <- prometheus.NewDesc("netcap_ebpf_packets_total", 
        "Total packets processed", nil, nil)
    ch <- prometheus.NewDesc("netcap_ebpf_bytes_total", 
        "Total bytes processed", nil, nil)
}

func (c *ebpfPrometheusCollector) Collect(ch chan<- prometheus.Metric) {
    metrics := c.metrics.GetMetrics()
    
    for name, value := range metrics {
        desc := prometheus.NewDesc("netcap_ebpf_"+name, name, nil, nil)
        ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, 
            float64(value))
    }
}
```

---

### 6. TCP Stream Sampling

#### Current State

All TCP segments go through full reassembly in `reassembly/`.

#### eBPF Solution

Implement intelligent stream sampling/filtering:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Sampling configuration
struct sample_config {
    __u32 rate;       // 1 in N packets
    __u32 max_bytes;  // Max bytes per flow
    __u8 enabled;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sample_config);
} config SEC(".maps");

// Per-flow byte counter for limiting
struct flow_limit {
    __u64 bytes_seen;
    __u8 sampling;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct flow_key);
    __type(value, struct flow_limit);
} flow_limits SEC(".maps");

SEC("socket")
int sample_stream(struct __sk_buff *skb)
{
    __u32 key = 0;
    struct sample_config *cfg = bpf_map_lookup_elem(&config, &key);
    if (!cfg || !cfg->enabled)
        return 1;  // Pass all
    
    // Get flow key and limit
    struct flow_key fkey = {};
    // ... populate flow key ...
    
    struct flow_limit *limit = bpf_map_lookup_elem(&flow_limits, &fkey);
    if (!limit) {
        struct flow_limit new_limit = {
            .bytes_seen = skb->len,
            .sampling = 1,
        };
        bpf_map_update_elem(&flow_limits, &fkey, &new_limit, BPF_ANY);
        return 1;  // Pass first packet
    }
    
    // Check byte limit
    if (cfg->max_bytes > 0 && limit->bytes_seen >= cfg->max_bytes) {
        return 0;  // Drop - already captured enough
    }
    
    limit->bytes_seen += skb->len;
    
    // Sampling: pass every Nth packet
    if (cfg->rate > 1) {
        static __u32 counter = 0;
        counter++;
        if (counter % cfg->rate != 0)
            return 0;  // Drop - not sampled
    }
    
    return 1;  // Pass
}

char LICENSE[] SEC("license") = "GPL";
```

---

## Proposed Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                              Linux Kernel                                  │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     │
│  │   XDP Program   │────►│   TC Program    │────►│ Socket Filter   │     │
│  │                 │     │                 │     │                 │     │
│  │ • Firewall      │     │ • Flow tracking │     │ • Sampling      │     │
│  │ • Early filter  │     │ • Protocol ID   │     │ • Rate limit    │     │
│  │ • Metrics       │     │ • Stats update  │     │                 │     │
│  └────────┬────────┘     └────────┬────────┘     └────────┬────────┘     │
│           │                       │                       │               │
│  ┌────────▼────────┐     ┌────────▼────────┐     ┌────────▼────────┐     │
│  │   Block Map     │     │   Flow Map      │     │   Config Map    │     │
│  │  (LPM Trie)     │     │   (Hash)        │     │   (Array)       │     │
│  │                 │     │                 │     │                 │     │
│  │ • IP blocklist  │     │ • Flow stats    │     │ • Sample rate   │     │
│  │ • CIDR ranges   │     │ • Protocol IDs  │     │ • Thresholds    │     │
│  │ • Whitelist     │     │ • Timestamps    │     │                 │     │
│  └─────────────────┘     └─────────────────┘     └─────────────────┘     │
│                                                                           │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                         Ring Buffer                                  │  │
│  │  • Packet events                                                     │  │
│  │  • New flow notifications                                            │  │
│  │  • Alerts                                                            │  │
│  └────────────────────────────────┬───────────────────────────────────┘  │
│                                   │                                       │
└───────────────────────────────────┼───────────────────────────────────────┘
                                    │
                                    │ Ring buffer reader
                                    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                           Netcap Userspace                                 │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     │
│  │  cilium/ebpf    │     │    Collector    │     │    Decoders     │     │
│  │                 │     │                 │     │                 │     │
│  │ • Load programs │────►│ • Packet loop   │────►│ • Protocol      │     │
│  │ • Manage maps   │     │ • Worker pool   │     │ • Stream        │     │
│  │ • Read events   │     │ • Reassembly    │     │ • Custom        │     │
│  └─────────────────┘     └─────────────────┘     └─────────────────┘     │
│           │                                                               │
│           │              ┌─────────────────┐     ┌─────────────────┐     │
│           │              │   DPI Engine    │     │  Audit Records  │     │
│           └─────────────►│                 │────►│                 │     │
│                          │ • nDPI          │     │ • Protobuf      │     │
│                          │ • libprotoident │     │ • Storage       │     │
│                          │ • go-dpi        │     │ • Export        │     │
│                          └─────────────────┘     └─────────────────┘     │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Plan

### Phase 1: XDP Packet Capture (High Priority)

**Goal**: Replace AF_PACKET with XDP for 10x+ performance improvement

**Tasks**:
1. Create `bpf/` directory with C source files
2. Add `bpf2go` generation to build process
3. Implement `collector/live_linux_xdp.go`
4. Add CLI flag `--capture-mode=xdp|afpacket|pcap`
5. Benchmark against existing capture methods

**Estimated effort**: 2-3 weeks

**Files to create/modify**:
- `bpf/xdp_capture.c` (new)
- `collector/live_linux_xdp.go` (new)
- `collector/config.go` (add CaptureMode option)
- `go.mod` (add cilium/ebpf)

### Phase 2: eBPF Firewall Module (High Priority)

**Goal**: Sub-microsecond blocking replacing iptables

**Tasks**:
1. Implement XDP firewall program with LPM trie
2. Create `firewall/ebpf_manager.go`
3. Add fallback to iptables for non-Linux/older kernels
4. Integrate with existing rules engine for automated blocking

**Estimated effort**: 2 weeks

**Files to create/modify**:
- `bpf/firewall.c` (new)
- `firewall/ebpf_manager.go` (new)
- `firewall/manager.go` (add interface abstraction)

### Phase 3: Kernel Flow Tracking (Medium Priority)

**Goal**: Offload connection tracking to kernel

**Tasks**:
1. Implement TC-based flow tracker
2. Create Go bindings for flow map access
3. Add flow export for userspace consumers
4. Integrate with existing flow structures

**Estimated effort**: 2-3 weeks

### Phase 4: Kernel Metrics (Medium Priority)

**Goal**: Lock-free per-CPU metrics

**Tasks**:
1. Implement metrics BPF program
2. Create Prometheus exporter for BPF maps
3. Replace userspace atomic counters
4. Add histogram support

**Estimated effort**: 1-2 weeks

### Phase 5: Protocol Pre-Detection (Lower Priority)

**Goal**: Fast-path protocol identification

**Tasks**:
1. Implement signature matching in TC program
2. Create protocol cache map
3. Integrate with DPI pipeline
4. Add confidence scoring

**Estimated effort**: 2 weeks

---

## Technical Requirements

### Kernel Version Requirements

| Feature | Minimum Kernel | Recommended |
|---------|---------------|-------------|
| XDP basic | 4.8 | 5.4+ |
| XDP redirect | 4.14 | 5.4+ |
| BPF ring buffer | 5.8 | 5.8+ |
| BPF per-CPU maps | 4.6 | 5.4+ |
| BPF LPM trie | 4.11 | 5.4+ |
| BTF support | 5.2 | 5.4+ |
| CO-RE | 5.5 | 5.8+ |

**Recommendation**: Target Linux 5.4+ (LTS) as minimum, with 5.10+ (LTS) preferred.

### Build Requirements

```bash
# Dependencies for building BPF programs
apt install clang llvm libbpf-dev

# Or for newer libbpf
git clone https://github.com/libbpf/libbpf
cd libbpf/src && make install
```

### Go Module Addition

```go
// go.mod
require github.com/cilium/ebpf v0.20.0
```

### Build Tags

```go
//go:build linux && ebpf
// +build linux,ebpf
```

### Privileges

eBPF requires elevated privileges:
- `CAP_BPF` (Linux 5.8+)
- `CAP_NET_ADMIN` (for XDP/TC attachment)
- `CAP_SYS_ADMIN` (older kernels, or for some map types)

---

## Performance Comparison

### Expected Performance Improvements

| Metric | Current (AF_PACKET) | With eBPF | Improvement |
|--------|--------------------:|----------:|------------:|
| Packet capture rate | 1-2 Mpps | 10-20 Mpps | 10x |
| Capture latency | 10-50 μs | 1-5 μs | 10x |
| Firewall rule update | 5-50 ms | 1-10 μs | 5000x |
| Firewall lookup | O(n) | O(1) | Significant |
| Flow tracking overhead | Per-packet | Batched | 5-10x |
| Metrics update | Atomic ops | Lock-free | 2-3x |

### Memory Overhead

| Component | Memory Usage |
|-----------|-------------|
| XDP program | ~100 KB |
| Ring buffer | 256 MB (configurable) |
| Flow map (1M flows) | ~80 MB |
| Block map (100K entries) | ~10 MB |
| Metrics maps | ~1 MB |

---

## Limitations and Considerations

### Platform Limitations

- **Linux-only**: eBPF is Linux-specific
  - macOS: Continue using libpcap
  - Windows: Continue using libpcap/npcap
- **Kernel version**: Requires Linux 5.4+
- **Architecture**: Best support on amd64, arm64

### Operational Considerations

- **Privileges**: Requires root or CAP_BPF/CAP_NET_ADMIN
- **Debugging**: BPF debugging more complex than userspace
- **Portability**: BPF programs may need recompilation for different kernels (CO-RE helps)
- **Complexity**: Adds C code and cross-compilation requirements

### Fallback Strategy

```go
func (c *Collector) CollectLive(iface, bpf string, ctx context.Context) error {
    // Try XDP first on Linux
    if runtime.GOOS == "linux" && c.config.CaptureMode == "xdp" {
        err := c.CollectLiveXDP(iface, ctx)
        if err == nil {
            return nil
        }
        log.Printf("XDP capture failed, falling back to AF_PACKET: %v", err)
    }
    
    // Fallback to existing implementation
    return c.collectLiveAFPacket(iface, bpf, ctx)
}
```

### Testing Requirements

- Unit tests for BPF map operations
- Integration tests on real hardware
- Performance benchmarks vs current implementation
- Compatibility testing across kernel versions

---

## References

### eBPF Resources

- [cilium/ebpf GitHub](https://github.com/cilium/ebpf)
- [ebpf-go.dev Documentation](https://ebpf-go.dev/)
- [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
- [Linux BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/index.html)

### Related Projects

- [Cilium](https://cilium.io/) - eBPF-based networking for Kubernetes
- [Falco](https://falco.org/) - eBPF-based runtime security
- [Pixie](https://px.dev/) - eBPF-based observability
- [bpftrace](https://github.com/iovisor/bpftrace) - High-level tracing language

### XDP Examples

- [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial)
- [cilium/ebpf examples](https://github.com/cilium/ebpf/tree/main/examples)

---

## Conclusion

Integrating cilium/ebpf into Netcap would provide significant performance improvements for Linux deployments, particularly for:

1. **High-throughput environments** (10Gbps+)
2. **Real-time blocking/filtering** scenarios
3. **Large-scale flow tracking** requirements
4. **Low-latency metrics collection**

The phased implementation approach allows incremental adoption while maintaining backward compatibility with existing capture methods on non-Linux platforms.

The eBPF ecosystem is mature and production-ready, with cilium/ebpf being the de facto standard for Go-based eBPF development. This integration would position Netcap alongside other modern network analysis tools that leverage kernel-level programmability.

