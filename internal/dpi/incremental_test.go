//go:build !nodpi

package dpi

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	godpi "github.com/dreadl0ck/go-dpi"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type performanceCaptureReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

func TestIncrementalBudgetAndRelease(t *testing.T) {
	for _, modules := range []string{"ndpi", "lpi", "lpi,ndpi", ""} {
		t.Run(modules, func(t *testing.T) {
			p, err := newIncrementalPool(parseModules(modules), 1, 8, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			defer p.close()
			for i := 0; i < 100; i++ {
				for protocol := range p.classify(performancePacket(t, 1, false, false, i)) {
					if protocol != "NO_FIRSTPKT" {
						t.Fatalf("unidentified fixture: %s", protocol)
					}
				}
			}
			s := p.shards[0]
			want := uint64(10)
			if s.processed != want {
				t.Fatalf("processed %d packets, want %d", s.processed, want)
			}
			for _, f := range s.flows {
				if !s.worker.Complete(&f.native) || f.goFlow != nil {
					t.Fatal("budget did not release inspection state")
				}
			}
			p.flush()
			if len(s.flows) != 0 || s.head != nil || s.tail != nil {
				t.Fatal("flush retained flows")
			}
		})
	}
}

func TestIncrementalEvictionAndExpiry(t *testing.T) {
	p, err := newIncrementalPool(parseModules("ndpi"), 1, 2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	for i := 1; i <= 3; i++ {
		p.classify(performancePacket(t, uint32(i), false, false))
	}
	s := p.shards[0]
	key, _, _ := packetKey(performancePacket(t, 1, false, false))
	if len(s.flows) != 2 || s.flows[key] != nil {
		t.Fatal("capacity eviction failed")
	}
	s.Lock()
	s.expire(time.Now().Add(2 * time.Minute))
	s.Unlock()
	if len(s.flows) != 0 {
		t.Fatal("expiry retained native flows")
	}
}

func TestIncrementalFlowIdentity(t *testing.T) {
	forward := performancePacket(t, 1, true, false)
	reverse := performancePacket(t, 1, true, true)
	k1, d1, _ := packetKey(forward)
	k2, d2, _ := packetKey(reverse)
	if k1 != k2 || d1 == d2 {
		t.Fatal("bidirectional identity mismatch")
	}
	k3, _, _ := packetKey(performancePacket(t, 2, true, false))
	if k1 == k3 {
		t.Fatal("different addresses collide")
	}
	if _, _, ok := packetKey(nil); ok {
		t.Fatal("nil packet accepted")
	}
	forward.TransportLayer().(*layers.TCP).SrcPort = 80
	reverse.TransportLayer().(*layers.TCP).DstPort = 80
	k1, _, _ = packetKey(forward)
	k2, _, _ = packetKey(reverse)
	if k1 != k2 {
		t.Fatal("equal-port reverse flow was split")
	}
}

func TestIncrementalRepeatedEnrichment(t *testing.T) {
	p, err := newIncrementalPool(parseModules("ndpi"), 1, 8, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	for i := 0; i < 100; i++ {
		packet := performancePacket(t, 1, false, false, i)
		for j := 0; j < 3; j++ {
			p.classify(packet)
		}
	}
	if p.shards[0].processed != 10 {
		t.Fatal("repeated enrichment consumed extra inspection budget")
	}
	p.flush()
	if p.shards[0].lastMetadata != nil {
		t.Fatal("flush retained packet scratch state")
	}
}

func TestIncrementalSCTPIdentity(t *testing.T) {
	base := performancePacket(t, 1, false, false)
	ip := *base.NetworkLayer().(*layers.IPv4)
	ip.Protocol = layers.IPProtocolSCTP
	sctp := &layers.SCTP{SrcPort: 40000, DstPort: 49152}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		base.LinkLayer().(*layers.Ethernet), &ip, sctp); err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	key, _, valid := packetKey(packet)
	if !valid || key.protocol != 132 {
		t.Fatal("SCTP transport was dropped")
	}
}

func TestIncrementalConfig(t *testing.T) {
	p, err := configuredIncrementalPool(parseModules("go"), RuntimeConfig{Workers: 2, MaxFlows: 5})
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	if len(p.shards) != 2 || p.shards[0].limit+p.shards[1].limit != 5 {
		t.Fatal("configured flow limit changed")
	}
	if _, err := configuredIncrementalPool(parseModules("go"), RuntimeConfig{Workers: -1}); err == nil {
		t.Fatal("negative worker count accepted")
	}
}

func TestIncrementalConcurrentNativeLifecycle(t *testing.T) {
	Destroy()
	t.Cleanup(Destroy)
	for round := 0; round < 3; round++ {
		Init("lpi,ndpi")
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			packet := performancePacket(t, uint32(i+1), true, false)
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 64; j++ {
					GetProtocols(packet)
				}
			}()
		}
		wg.Add(1)
		go func() { defer wg.Done(); Destroy() }()
		wg.Wait()
		if IsEnabled() {
			t.Fatal("native lifecycle remained enabled")
		}
	}
}

// Run separate processes under /usr/bin/time -l; Go allocation counters exclude native memory.
func TestCIntegrationMemory(t *testing.T) {
	if os.Getenv("DPI_MEMORY_PROBE") != "1" {
		t.Skip("set DPI_MEMORY_PROBE=1 for the process RSS probe")
	}
	classify, flush := setupPerformance(t, "ndpi")
	if cardinality := os.Getenv("DPI_MEMORY_CARDINALITY"); cardinality != "" {
		count, err := strconv.Atoi(cardinality)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < count; i++ {
			classify(performancePacket(t, uint32(i+1), false, false))
		}
		return
	}
	packets := make([][]gopacket.Packet, 256)
	for i := range packets {
		packets[i] = make([]gopacket.Packet, 10)
		for j := range packets[i] {
			packets[i][j] = performancePacket(t, uint32(i+1), false, false, j)
		}
	}
	for batch := 0; batch < 40; batch++ {
		flush()
		for _, flow := range packets {
			for _, packet := range flow {
				classify(packet)
			}
		}
	}
	flush()
}

func TestIncrementalCorpusParity(t *testing.T) {
	dir := os.Getenv("DPI_CORPUS")
	if dir == "" {
		t.Skip("set DPI_CORPUS to the go-dpi dumps directory")
	}
	for _, name := range []string{"nginx", "ssh", "smtp", "syslog", "openvpn", "mqtt", "modbus", "pgsql", "quic", "wireguard"} {
		t.Run(name, func(t *testing.T) {
			file, err := os.Open(filepath.Join(dir, name+".pcap"))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			buffer := bufio.NewReader(file)
			magic, err := buffer.Peek(4)
			if err != nil {
				t.Fatal(err)
			}
			var reader performanceCaptureReader
			if bytes.Equal(magic, []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
				reader, err = pcapgo.NewNgReader(buffer, pcapgo.DefaultNgReaderOptions)
			} else {
				reader, err = pcapgo.NewReader(buffer)
			}
			if err != nil {
				t.Fatal(err)
			}
			var packets []gopacket.Packet
			for len(packets) < 10000 {
				data, info, err := reader.ReadPacketData()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
				packet.Metadata().CaptureInfo = info
				if packet.NetworkLayer() != nil && packet.NetworkLayer().LayerType() == layers.LayerTypeIPv4 && packet.TransportLayer() != nil {
					packets = append(packets, packet)
				}
			}
			for _, modules := range []string{"ndpi", "lpi", "lpi,ndpi"} {
				var detected [2]map[string]bool
				for i, mode := range []string{"1", ""} {
					t.Setenv("DPI_BENCH_LEGACY", mode)
					classify, flush := setupPerformance(t, modules)
					detected[i] = make(map[string]bool)
					for _, packet := range packets {
						for protocol := range classify(packet) {
							if protocol != "NO_FIRSTPKT" && protocol != "UNSUPPORTED" && protocol != "UDP" {
								detected[i][protocol] = true
							}
						}
					}
					flush()
					if mode != "" {
						godpi.Destroy()
					} else {
						Destroy()
					}
				}
				for protocol := range detected[0] {
					if !detected[1][protocol] {
						t.Errorf("%s lost legacy detection %s", modules, protocol)
					}
				}
				additional := map[string][]string{
					"nginx/lpi": {"HTTPS"}, "smtp/lpi": {"SMTP"}, "pgsql/lpi": {"POSTGRESQL"},
					"openvpn/lpi": {"OPENVPN", "UDP_OPENVPN"}, "quic/lpi": {"UDP_QUIC"}, "quic/lpi,ndpi": {"UDP_QUIC"},
					"wireguard/ndpi": {"WIREGUARD"}, "wireguard/lpi,ndpi": {"WIREGUARD"},
				}[name+"/"+modules]
				for _, protocol := range additional {
					if !detected[1][protocol] {
						t.Errorf("%s lost corrected detection %s", modules, protocol)
					}
				}
				for protocol := range detected[1] {
					if detected[0][protocol] {
						continue
					}
					allowed := false
					for _, expected := range additional {
						if protocol == expected {
							allowed = true
						}
					}
					if !allowed {
						t.Errorf("%s unexpected additional detection %s", modules, protocol)
					}
				}
				t.Logf("%s: %d packets; legacy %v; incremental %v", modules, len(packets), detected[0], detected[1])
			}
		})
	}
}
