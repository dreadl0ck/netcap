package packet

import (
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/dpi"
)

func connectionBenchmarkSetup(b *testing.B) {
	b.Helper()
	if dpi.IsEnabled() {
		b.Fatal("connection baseline requires DPI disabled")
	}
	previous := conf
	if conf == nil {
		conf = &decoderconfig.Config{}
	}
	ResetConnections()
	b.Cleanup(func() {
		ResetConnections()
		conf = previous
	})
}

// Packets are eagerly decoded and never mutated after construction, including metadata.
func connectionBenchmarkPackets(tb testing.TB, count int) []gopacket.Packet {
	tb.Helper()
	packets := make([]gopacket.Packet, count)
	for i := range packets {
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
			DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
			SrcIP: net.IPv4(10, byte(i>>8), byte(i), 1),
			DstIP: net.IPv4(192, 0, 2, 10),
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(32768 + i%32768), DstPort: 80,
			Seq: 1001, Ack: 2001, ACK: true, PSH: true, Window: 65535,
		}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			tb.Fatal(err)
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			eth, ip, tcp, gopacket.Payload("GET /api/v1/status HTTP/1.1\r\nHost: example.com\r\nUser-Agent: netcap-benchmark/1.0\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n")); err != nil {
			tb.Fatal(err)
		}
		p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: false, NoCopy: false})
		if err := p.ErrorLayer(); err != nil {
			tb.Fatal(err.Error())
		}
		p.Metadata().CaptureInfo = gopacket.CaptureInfo{
			Timestamp: time.Unix(1700000000, 0), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes()),
		}
		packets[i] = p
	}
	return packets
}

func BenchmarkConnectionUpdates(b *testing.B) {
	for _, mode := range []string{"ManyFlows", "HotFlow", "Skewed80PercentHot"} {
		b.Run(mode, func(b *testing.B) {
			connectionBenchmarkSetup(b)
			packets := connectionBenchmarkPackets(b, max(1024, runtime.GOMAXPROCS(0)+1))
			for _, p := range packets {
				handlePacket(p)
			}
			if got := conns.Size(); got != len(packets) {
				b.Fatalf("warmed %d connections, want %d", got, len(packets))
			}
			var next atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				index := int(next.Add(1))
				p := packets[index]
				switch mode {
				case "ManyFlows":
					for pb.Next() {
						handlePacket(p)
					}
				case "HotFlow":
					p = packets[0]
					for pb.Next() {
						handlePacket(p)
					}
				case "Skewed80PercentHot":
					// Offset each worker's deterministic 80/20 mix; no shared RNG or per-packet atomic.
					n := index % 5
					for pb.Next() {
						if n == 0 {
							handlePacket(p)
						} else {
							handlePacket(packets[0])
						}
						n = (n + 1) % 5
					}
				}
			})
			b.StopTimer()
		})
	}
}

func BenchmarkConnectionNewFlowChurn(b *testing.B) {
	connectionBenchmarkSetup(b)
	packets := connectionBenchmarkPackets(b, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for done := 0; done < b.N; {
		b.StopTimer()
		ResetConnections()
		batch := min(len(packets), b.N-done)
		b.StartTimer()
		for _, p := range packets[:batch] {
			handlePacket(p)
		}
		done += batch
	}
	b.StopTimer()
}
