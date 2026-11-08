package collector

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func shardingTCPPacket(t *testing.T, ipv6, reverse bool, port layers.TCPPort, mac byte) gopacket.Packet {
	t.Helper()
	src, dst := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	if ipv6 {
		src, dst = net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	}
	sport, dport := port, layers.TCPPort(1003)
	if reverse {
		src, dst, sport, dport = dst, src, dport, sport
	}
	var network gopacket.SerializableLayer = &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
	var first gopacket.Decoder = layers.LayerTypeIPv4
	etherType := layers.EthernetTypeIPv4
	if ipv6 {
		network = &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
		first, etherType = layers.LayerTypeIPv6, layers.EthernetTypeIPv6
	}
	parts := []gopacket.SerializableLayer{network, &layers.TCP{SrcPort: sport, DstPort: dport, SYN: true}}
	if mac != 0 {
		parts = append([]gopacket.SerializableLayer{&layers.Ethernet{
			SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, mac}, DstMAC: net.HardwareAddr{0, 5, 6, 7, 8, mac + 1}, EthernetType: etherType,
		}}, parts...)
		first = layers.LayerTypeEthernet
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, parts...); err != nil {
		t.Fatal(err)
	}
	p := gopacket.NewPacket(buf.Bytes(), first, gopacket.Default)
	if err := p.ErrorLayer(); err != nil {
		t.Fatal(err.Error())
	}
	return p
}

func TestSymmetricWorkerIndexTCP(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, workers := range []int{0, 1, 2, 3, 4, 7, 16} {
			t.Run(fmt.Sprintf("ipv6=%t/workers=%d", ipv6, workers), func(t *testing.T) {
				c := &Collector{numWorkers: workers}
				// These IPv4 addresses and ports cancelled to zero in the old XOR hash.
				p := shardingTCPPacket(t, ipv6, false, 1000, 0)
				want := c.getSymmetricWorkerIndex(p)
				for range 5 {
					for _, reverse := range []bool{false, true} {
						for _, mac := range []byte{0, 1, 20} {
							if got := c.getSymmetricWorkerIndex(shardingTCPPacket(t, ipv6, reverse, 1000, mac)); got != want {
								t.Fatalf("reverse=%t mac=%d: worker=%d, want %d", reverse, mac, got, want)
							}
						}
					}
				}
				if c.next.Load() != 0 {
					t.Fatal("identifiable TCP flow used round robin")
				}
				if workers <= 1 {
					if want != 0 {
						t.Fatalf("worker=%d, want 0", want)
					}
					return
				}
				counts := make([]int, workers)
				for port := 10000; port < 11024; port++ {
					p := shardingTCPPacket(t, ipv6, false, layers.TCPPort(port), 0)
					got := c.getSymmetricWorkerIndex(p)
					hash := p.NetworkLayer().NetworkFlow().FastHash() ^ p.Layer(layers.LayerTypeTCP).(*layers.TCP).TransportFlow().FastHash()
					if want := int(hash % uint64(workers)); got != want {
						t.Fatalf("worker=%d, want FastHash worker %d", got, want)
					}
					counts[got]++
					if reverse := c.getSymmetricWorkerIndex(shardingTCPPacket(t, ipv6, true, layers.TCPPort(port), 0)); reverse != got {
						t.Fatalf("port=%d: forward=%d reverse=%d", port, got, reverse)
					}
				}
				for worker, count := range counts {
					if count < 1024/workers/2 || count > 2*1024/workers {
						t.Fatalf("poor distribution: worker=%d count=%d counts=%v", worker, count, counts)
					}
				}
			})
		}
	}
}

type shardingNetworkFlow struct {
	*layers.IPv4
	flow gopacket.Flow
}

func (n shardingNetworkFlow) NetworkFlow() gopacket.Flow { return n.flow }

func TestSymmetricWorkerIndexZeroHash(t *testing.T) {
	for _, mac := range []byte{0, 1, 20} {
		for _, reverse := range []bool{false, true} {
			p := shardingTCPPacket(t, false, reverse, 1000, mac)
			tcp := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
			// Equal component hashes force a combined zero hash.
			p = gopacket.NewPacket(nil, gopacket.DecodeFunc(func(_ []byte, b gopacket.PacketBuilder) error {
				b.SetNetworkLayer(shardingNetworkFlow{flow: tcp.TransportFlow()})
				b.AddLayer(tcp)
				b.SetTransportLayer(tcp)
				if mac != 0 {
					b.SetLinkLayer(&layers.Ethernet{SrcMAC: net.HardwareAddr{mac}, DstMAC: net.HardwareAddr{mac + 1}})
				}
				return nil
			}), gopacket.Default)
			for _, workers := range []int{2, 3, 4, 7, 16} {
				c := &Collector{numWorkers: workers}
				for range 5 {
					if got := c.getSymmetricWorkerIndex(p); got != 0 || c.next.Load() != 0 {
						t.Fatalf("mac=%d reverse=%t workers=%d: zero hash worker=%d next=%d", mac, reverse, workers, got, c.next.Load())
					}
				}
			}
		}
	}
}

func TestSymmetricWorkerIndexTCPSelection(t *testing.T) {
	for _, workers := range []int{2, 3, 4, 7, 16} {
		c := &Collector{numWorkers: workers}
		pipeline := packetview.New(packetview.Limits{})
		want := -1
		for _, reverse := range []bool{false, true} {
			for port := 2000; port < 2032; port++ {
				raw := testutil.Tunnel("vxlan", 42, testutil.TCP(true, reverse, 1, 0, "S", ""))
				binary.BigEndian.PutUint16(raw[20:22], uint16(port))
				p := pipeline.Process(testutil.Packet(testutil.Ethernet(raw), 0, 1), 1).Packet
				if p == nil || p.NetworkLayer().LayerType() != layers.LayerTypeIPv6 {
					t.Fatal("inner packet missing")
				}
				if _, ok := p.TransportLayer().(*layers.TCP); !ok {
					t.Fatal("outer UDP selected")
				}
				got := c.getSymmetricWorkerIndex(p)
				if want < 0 {
					want = got
				}
				if got != want {
					t.Fatalf("workers=%d reverse=%v entropy=%d got=%d want=%d", workers, reverse, port, got, want)
				}
			}
		}
	}
}

func TestSymmetricWorkerIndexFallback(t *testing.T) {
	for _, workers := range []int{1, 2, 3, 7, 16} {
		c := &Collector{numWorkers: workers}
		p := gopacket.NewPacket(nil, gopacket.LayerTypePayload, gopacket.Default)
		for i := range 2 * workers {
			if got := c.getSymmetricWorkerIndex(p); got != i%workers {
				t.Fatalf("workers=%d packet=%d: worker=%d", workers, i, got)
			}
		}
	}
}
