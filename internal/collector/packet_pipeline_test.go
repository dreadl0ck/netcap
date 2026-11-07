package collector

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/packet"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/networkdetect"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/dreadl0ck/netcap/types"
)

type pipelineFixture struct {
	name, tunnel, fragmentation string
	v6                          bool
	id                          uint32
}

func pipelineCases() []pipelineFixture {
	return []pipelineFixture{
		{name: "gre", tunnel: "gre", id: 1}, {name: "gre-ethernet", tunnel: "gre-ethernet"},
		{name: "erspan-i", tunnel: "erspan-i"}, {name: "erspan-ii", tunnel: "erspan-ii", id: 2}, {name: "erspan-iii", tunnel: "erspan-iii", id: 3},
		{name: "vxlan-a", tunnel: "vxlan", id: 4}, {name: "vxlan-b", tunnel: "vxlan", id: 5},
		{name: "geneve", tunnel: "geneve", id: 6}, {name: "nested", tunnel: "geneve-gre", id: 7},
		{name: "fragment4", fragmentation: "inner"}, {name: "fragment6", fragmentation: "inner", v6: true},
		{name: "inner-fragments", tunnel: "vxlan", id: 8, fragmentation: "inner"},
		{name: "outer-fragments", tunnel: "geneve-gre", id: 9, fragmentation: "outer"},
	}
}

func pipelinePCAP(t *testing.T, path string) (int, int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err = w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	count := 0
	var wire int64
	write := func(ip []byte) {
		raw := testutil.Ethernet(ip)
		count++
		wire += int64(len(raw))
		if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(count)*1000000), Length: len(raw), CaptureLength: len(raw)}, raw); err != nil {
			t.Fatal(err)
		}
	}
	for step := 0; step < 8; step++ {
		for _, c := range pipelineCases() {
			request := fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: pipeline.invalid\r\n\r\n", c.name)
			body := "response-" + c.name
			response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
			seq, ack, flags, reverse, payload := uint32(1001), uint32(2001), "A", false, ""
			switch step {
			case 0:
				seq, ack, flags = 1000, 0, "S"
			case 1:
				seq, ack, flags, reverse = 2000, 1001, "SA", true
			case 3:
				flags, payload = "PA", request
			case 4:
				seq, ack, flags, reverse, payload = 2001, uint32(1001+len(request)), "PA", true, response
			case 5:
				seq, ack, flags = uint32(1001+len(request)), uint32(2001+len(response)), "FA"
			case 6:
				seq, ack, flags, reverse = uint32(2001+len(response)), uint32(1002+len(request)), "FA", true
			case 7:
				seq, ack = uint32(1002+len(request)), uint32(2002+len(response))
			}
			ip := testutil.TCP(c.v6, reverse, seq, ack, flags, payload)
			wrap := func(ip []byte) []byte {
				if c.tunnel != "" {
					return testutil.Tunnel(c.tunnel, c.id, ip)
				}
				return ip
			}
			fragment := func(ip []byte) [][]byte {
				h := 20
				if ip[0]>>4 == 6 {
					h = 40
				}
				// Noninitial fragment first, including split TCP headers on SYNs.
				return [][]byte{testutil.Fragment(ip, uint32(100+step), 16, len(ip)-h, false), testutil.Fragment(ip, uint32(100+step), 0, 16, true)}
			}
			switch c.fragmentation {
			case "inner":
				for _, f := range fragment(ip) {
					write(wrap(f))
				}
			case "outer":
				for _, f := range fragment(wrap(ip)) {
					write(f)
				}
			default:
				write(wrap(ip))
			}
		}
	}
	for _, v6 := range []bool{false, true} {
		for _, udp := range []bool{false, true} {
			protocol := layers.IPProtocolICMPv4
			payload := testutil.Serialize(&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0), Id: 23, Seq: 12}, gopacket.Payload("echo pipeline payload"))
			if v6 {
				protocol = layers.IPProtocolICMPv6
				payload = append([]byte{128, 0, 0, 0, 0, 23, 0, 12}, []byte("echo pipeline payload")...)
			}
			if udp {
				protocol = layers.IPProtocolUDP
				payload = testutil.Serialize(&layers.UDP{SrcPort: 5555, DstPort: 5556}, gopacket.Payload("UDP pipeline payload"))
			}
			ip := testutil.IP(v6, false, protocol, payload)
			id := uint32(500)
			if udp {
				id++
			}
			write(testutil.Fragment(ip, id, 8, len(payload), false))
			write(testutil.Fragment(ip, id, 0, 8, true))
		}
	}
	return count, wire
}

// Subprocess isolation matches the existing worker replay tests: decoder writers
// and stream singletons are process-global. Assertions read persisted protobufs.
func TestPacketPipelineProcess(t *testing.T) {
	input := os.Getenv("NETCAP_PIPELINE_INPUT")
	if input == "" {
		return
	}
	workers, _ := strconv.Atoi(os.Getenv("NETCAP_PIPELINE_WORKERS"))
	c := New(Config{Workers: workers, PacketBufferSize: 8, ReassembleConnections: true, CaptureEvidence: true, NoSignalHandling: true, NoPrompt: true,
		BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Default,
		DecoderConfig: &config.Config{Out: os.Getenv("NETCAP_PIPELINE_OUT"), Quiet: true, IncludeDecoders: "HTTP,Connection,IPv4,IPv6,TCP,UDP,ICMPv4,ICMPv6", Proto: true, AddContext: true,
			Buffer: true, MemBufferSize: 4096, WaitForConnections: true, NoOptCheck: true, FlushEvery: 7, ClosePendingTimeOut: 5 * time.Second, CloseInactiveTimeOut: time.Minute,
			StreamBufferSize: 8, StreamDecoderBufSize: 8, NumStreamWorkers: 2, BannerSize: 256}})
	if err := c.CollectPcap(input); err != nil {
		t.Fatal(err)
	}
	want, _ := strconv.Atoi(os.Getenv("NETCAP_PIPELINE_PACKETS"))
	if c.GetNumPackets() != int64(want) || c.admittedPackets != uint64(want) {
		t.Fatalf("capture count %d/%d want %d", c.GetNumPackets(), c.admittedPackets, want)
	}
	if s := c.PacketPipelineStats(); s.Completed != 36 || s.BufferedBytes != 0 || s.Datagrams != 0 || s.Rejected != 0 || s.Malformed != 0 {
		t.Fatalf("pipeline stats %+v", s)
	}
}

func pipelineRead(t *testing.T, out, name string, newRecord func() proto.Message) []proto.Message {
	t.Helper()
	r, err := netio.Open(filepath.Join(out, name+".ncap"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	var records []proto.Message
	for {
		m := newRecord()
		err = r.Next(m)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, m)
	}
	return records
}

func TestPacketPipelinePCAP(t *testing.T) {
	input := filepath.Join(t.TempDir(), "packet-pipeline.pcap")
	count, wire := pipelinePCAP(t, input)
	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprintf("workers=%d", workers), func(t *testing.T) {
			out := t.TempDir()
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestPacketPipelineProcess$", "-test.count=1")
			cmd.Env = append(os.Environ(), "NETCAP_PIPELINE_INPUT="+input, "NETCAP_PIPELINE_OUT="+out, fmt.Sprintf("NETCAP_PIPELINE_WORKERS=%d", workers), fmt.Sprintf("NETCAP_PIPELINE_PACKETS=%d", count))
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("collector replay: %v\n%s", err, output)
			}
			http := pipelineRead(t, out, "HTTP", func() proto.Message { return &types.HTTP{} })
			urls := map[string]int{}
			for _, m := range http {
				r := m.(*types.HTTP)
				urls[r.URL]++
				if r.StatusCode != 200 || r.Method != "GET" || r.Host != "pipeline.invalid" || r.SrcPort != 40000 || r.DstPort != 80 || (r.SrcIP != "10.0.0.1" && r.SrcIP != "2001:db8::1") {
					t.Fatalf("HTTP attribution/pairing: %v", r)
				}
			}
			for _, c := range pipelineCases() {
				if urls["/"+c.name] != 1 {
					t.Fatalf("HTTP %s count=%d all=%v", c.name, urls["/"+c.name], urls)
				}
			}
			if len(http) != len(pipelineCases()) {
				t.Fatalf("HTTP records %d", len(http))
			}
			conns := pipelineRead(t, out, "Connection", func() proto.Message { return &types.Connection{} })
			var packets, bytes int64
			scopes := map[string]bool{}
			var cids []string
			for _, m := range conns {
				r := m.(*types.Connection)
				packets += r.NumPackets64
				bytes += r.TotalSize64
				if r.SrcIP == "192.0.2.1" || r.DstIP == "192.0.2.2" || r.NetworkScope == "" {
					t.Fatalf("outer/unspecified Connection: %v", r)
				}
				if r.TransportProto == "TCP" {
					key := r.NetworkScope + "/" + r.SrcIP
					if scopes[key] {
						t.Fatalf("duplicate scoped TCP connection %s", r.NetworkScope)
					}
					scopes[key] = true
					if r.NumPackets64 != 8 && r.NumPackets64 != 16 {
						t.Fatalf("Connection count %d", r.NumPackets64)
					}
					if r.SrcIP == "10.0.0.1" {
						cids = append(cids, r.CommunityID)
					}
				}
			}
			if packets != int64(count) || bytes != wire {
				t.Fatalf("Connection accounting packets=%d/%d bytes=%d/%d", packets, count, bytes, wire)
			}
			if len(scopes) != len(pipelineCases()) {
				t.Fatalf("scoped TCP connections %d", len(scopes))
			}
			for _, cid := range cids {
				if cid != cids[0] || !strings.HasPrefix(cid, "1:") {
					t.Fatalf("nonstandard/differing inner CommunityID %v", cids)
				}
			}
			tcp := pipelineRead(t, out, "TCP", func() proto.Message { return &types.TCP{} })
			if len(tcp) != 8*len(pipelineCases()) {
				t.Fatalf("transport duplicated/lost: %d TCP", len(tcp))
			}
			icmp4 := pipelineRead(t, out, "ICMPv4", func() proto.Message { return &types.ICMPv4{} })
			icmp6 := pipelineRead(t, out, "ICMPv6", func() proto.Message { return &types.ICMPv6{} })
			if len(icmp4) != 1 || len(icmp6) != 1 {
				t.Fatal("fragmented ICMP not decoded exactly once")
			}
		})
	}
}

func TestPipelineDetectionAndCommunityAttribution(t *testing.T) {
	p := packetview.New(packetview.Limits{})
	base := testutil.Packet(testutil.Ethernet(testutil.TCP(false, false, 1, 0, "S", "")), 0, 1)
	var lastScope networkdetect.Scope
	for _, id := range []uint32{1, 2} {
		r := p.Process(testutil.Packet(testutil.Ethernet(testutil.Tunnel("vxlan", id, testutil.TCP(false, false, 1, 0, "S", ""))), 0, 1), 1)
		if packet.CalcCommunityID(r.Packet) != packet.CalcCommunityID(base) {
			t.Fatal("inner CommunityID differs from direct flow")
		}
		events := networkdetect.PacketEvents(r.Packet, networkdetect.Scope{Sensor: "local", Interface: "pcap"})
		if len(events) != 1 || events[0].SrcIP != "10.0.0.1" || events[0].DstIP != "10.0.0.2" || events[0].DstPort != 80 {
			t.Fatalf("detection attribution %+v", events)
		}
		if id == 2 && events[0].Scope.Interface == lastScope.Interface {
			t.Fatal("detection VNI scopes merged")
		}
		lastScope = events[0].Scope
	}
}
