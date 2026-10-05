//go:build !nodpi

package dpi

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func performancePacket(tb testing.TB, id uint32, http bool, reverse bool, ordinal ...int) gopacket.Packet {
	tb.Helper()
	src := net.IP{10, byte(id >> 16), byte(id >> 8), byte(id)}
	dst := net.IP{192, 0, 2, 1}
	sport, dport := layers.TCPPort(40000), layers.TCPPort(49152)
	payload := []byte{0x91, 0xe7, 0x42, 0x83, 0xb1, 0xc4, 0x9e, 0x72}
	if http {
		dport = 80
		payload = []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	}
	if reverse {
		src, dst, sport, dport = dst, src, dport, sport
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: src, DstIP: dst, Protocol: layers.IPProtocolTCP}
	index := 0
	if len(ordinal) > 0 {
		index = ordinal[0]
	}
	tcp := &layers.TCP{SrcPort: sport, DstPort: dport, Seq: uint32(1 + index*len(payload)), ACK: true, Window: 65535}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}, ip, tcp, gopacket.Payload(payload))
	if err != nil {
		tb.Fatal(err)
	}
	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, 123000000), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}
	return p
}

// Every operation is a complete flow lifecycle; packet decoding is outside the timer.
func BenchmarkCIntegration(b *testing.B) {
	output := log.Writer()
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(output) })
	for _, modules := range []string{"ndpi", "lpi", "lpi,ndpi", ""} {
		for _, workload := range []struct {
			name    string
			packets int
			http    bool
			repeats int
		}{
			{"short_unknown", 1, false, 1}, {"budget_unknown", 10, false, 1}, {"long_unknown", 100, false, 1}, {"http", 10, true, 1},
			{"shared_packet", 10, false, 3},
		} {
			b.Run(fmt.Sprintf("%s/%s", modules, workload.name), func(b *testing.B) {
				classify, flush := setupPerformance(b, modules)
				// Fixed-size batches bound flow-cache memory independently of b.N.
				packets := make([][]gopacket.Packet, 512)
				for i := range packets {
					packets[i] = make([]gopacket.Packet, workload.packets)
					for j := range packets[i] {
						packets[i][j] = performancePacket(b, uint32(i+1), workload.http, false, j)
					}
				}
				for _, packet := range packets[0] {
					got := classify(packet)
					if !workload.http {
						for protocol := range got {
							if protocol != "NO_FIRSTPKT" {
								b.Fatalf("unidentified fixture classified as %v", got)
							}
						}
					}
					if workload.http && len(got) == 0 {
						b.Fatal("HTTP fixture not detected")
					}
				}
				flush()
				b.ReportAllocs()
				b.SetBytes(int64(len(packets[0][0].Data()) * workload.packets))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if i%len(packets) == 0 {
						flush()
					}
					for j := 0; j < workload.packets; j++ {
						for k := 0; k < workload.repeats; k++ {
							classify(packets[i%len(packets)][j])
						}
					}
				}
				b.ReportMetric(float64(workload.packets), "packets/op")
				b.ReportMetric(float64(workload.packets*workload.repeats), "calls/op")
			})
		}
	}
}

func BenchmarkCIntegrationHotParallel(b *testing.B) {
	output := log.Writer()
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(output) })
	classify, _ := setupPerformance(b, "ndpi")
	packets := make([]gopacket.Packet, 4096)
	for i := range packets {
		for j := 0; j < 10; j++ {
			packets[i] = performancePacket(b, uint32(i+1), false, false, j)
			classify(packets[i])
		}
	}
	var next atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			classify(packets[next.Add(1)%uint64(len(packets))])
		}
	})
}

func TestCIntegrationHTTPBidirectional(t *testing.T) {
	Destroy()
	Init("lpi,ndpi")
	t.Cleanup(Destroy)
	p := performancePacket(t, 7, true, false)
	if got := GetProtocols(p); len(got) == 0 {
		t.Fatal("HTTP was not detected")
	} else if got["HTTP"].Class == "" {
		t.Fatal("deduplication lost the LPI category")
	}
	if got := GetProtocols(performancePacket(t, 7, true, true)); len(got) == 0 {
		t.Fatal("reverse direction lost classification")
	}
}

// Keep an independent fixture check: both addresses, ports and protocol must contribute to flow identity.
func TestPerformancePacket(t *testing.T) {
	p := performancePacket(t, 0x010203, false, false)
	if p.ErrorLayer() != nil {
		t.Fatal(p.ErrorLayer().Error())
	}
	if binary.BigEndian.Uint32(p.NetworkLayer().NetworkFlow().Src().Raw()) != 0x0a010203 {
		t.Fatal("incorrect flow fixture")
	}
}
