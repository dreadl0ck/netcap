//go:build e2e

package e2e

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

// v0.16.12 evaluator follow-up at the CLI level: the shipped rule directory
// loads, its threshold rules separate browsing from scans and beacons, and a
// VRRP capture seals its aliased audit file.
func TestRecheck1612CLI(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	binary := filepath.Join(temp, "net")
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-tags=nodpi,noyara,nomagika", "-o", binary, "./cmd/net")
	build.Dir = root
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	capture := func(t *testing.T, name string, packets []timedPacket) string {
		t.Helper()
		input := filepath.Join(temp, name+".pcap")
		writeRawPCAP(t, input, packets)
		out := filepath.Join(temp, name)
		cmd := exec.CommandContext(ctx, binary, "capture", "--read", input, "--out", out, "--rules", filepath.Join(root, "internal/rules/examples"),
			"--quiet", "-y", "--geoDB=false", "--fileStorage", "")
		cmd.Env = append(os.Environ(), "NC_CONFIG_ROOT="+filepath.Join(temp, "config"))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("capture %s: %v\n%s", name, err, output)
		}
		return out
	}
	thresholdRules := []string{"SYN Scan Detection", "Multiple External Connections", "DNS Beaconing Pattern", "DNS Tunneling Volume"}
	expect := func(t *testing.T, out, fired string) {
		t.Helper()
		counts := alertCounts(t, out)
		for _, rule := range thresholdRules {
			if rule == fired && counts[rule] == 0 || rule != fired && counts[rule] != 0 {
				t.Errorf("%s: %d alerts (want firing=%t); all: %v", rule, counts[rule], rule == fired, counts)
			}
		}
	}
	src, resolver := net.IPv4(172, 16, 3, 122), net.IPv4(8, 8, 8, 8)
	base := time.Date(2026, 11, 19, 16, 0, 0, 0, time.UTC)

	t.Run("browse burst", func(t *testing.T) {
		var packets []timedPacket
		for i := range 150 {
			ts := base.Add(time.Duration(i) * 200 * time.Millisecond)
			packets = append(packets, tcpSYN(t, ts, src, net.IPv4(1, 2, byte(i/250), byte(i%250+1)), 443))
			name := fmt.Sprintf("cdn-%d.example.com", i)
			for j, qtype := range []layers.DNSType{layers.DNSTypeA, layers.DNSTypeAAAA, 65} {
				id := uint16(i*3 + j)
				packets = append(packets, dnsPacket(t, ts, src, resolver, id, name, qtype, false), dnsPacket(t, ts, resolver, src, id, name, qtype, true))
			}
		}
		expect(t, capture(t, "browse", packets), "")
	})
	t.Run("port scan", func(t *testing.T) {
		var packets []timedPacket
		for port := range 100 {
			packets = append(packets, tcpSYN(t, base.Add(time.Duration(port)*time.Millisecond), src, net.IPv4(10, 0, 0, 9), uint16(port+1)))
		}
		expect(t, capture(t, "scan", packets), "SYN Scan Detection")
	})
	t.Run("dns beacon", func(t *testing.T) {
		var packets []timedPacket
		for i := range 100 {
			packets = append(packets, dnsPacket(t, base.Add(time.Duration(i)*5*time.Second), src, resolver, uint16(i), "c2.example.org", layers.DNSTypeA, false))
		}
		expect(t, capture(t, "beacon", packets), "DNS Beaconing Pattern")
	})
	t.Run("vrrp", func(t *testing.T) {
		var packets []timedPacket
		for i := range 3 {
			packets = append(packets, vrrpAdvertisement(t, base.Add(time.Duration(i)*time.Second)))
		}
		out := capture(t, "vrrp", packets)
		if _, err := os.Stat(filepath.Join(out, "VRRP.ncap.gz")); err != nil {
			t.Fatal(err)
		}
		stages, err := os.ReadFile(filepath.Join(out, "audit-output-stages.json"))
		if err != nil || !strings.Contains(string(stages), `"VRRP.ncap.gz"`) {
			t.Fatalf("VRRP audit not sealed: %v\n%s", err, stages)
		}
	})
}

func alertCounts(t *testing.T, out string) map[string]int {
	t.Helper()
	counts := map[string]int{}
	f, err := os.Open(filepath.Join(out, "Alert.ncap.gz"))
	if errors.Is(err, os.ErrNotExist) {
		return counts
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	reader := delimited.NewReader(gz)
	if _, err := reader.Next(); err != nil { // header
		t.Fatal(err)
	}
	for {
		frame, err := reader.Next()
		if err == io.EOF {
			return counts
		}
		if err != nil {
			t.Fatal(err)
		}
		var alert types.Alert
		if err := proto.Unmarshal(frame, &alert); err != nil {
			t.Fatal(err)
		}
		counts[alert.RuleName]++
	}
}

type timedPacket struct {
	ts   time.Time
	data []byte
}

func writeRawPCAP(t *testing.T, path string, packets []timedPacket) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for _, p := range packets {
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: p.ts, CaptureLength: len(p.data), Length: len(p.data)}, p.data); err != nil {
			t.Fatal(err)
		}
	}
}

func serializeAt(t *testing.T, ts time.Time, network gopacket.SerializableLayer, rest ...gopacket.SerializableLayer) timedPacket {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	ip := network.(*layers.IPv4)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, ip.SrcIP[len(ip.SrcIP)-1]}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 1, 1}, EthernetType: layers.EthernetTypeIPv4}
	all := append([]gopacket.SerializableLayer{eth, network}, rest...)
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, all...); err != nil {
		t.Fatal(err)
	}
	return timedPacket{ts: ts, data: append([]byte(nil), buf.Bytes()...)}
}

func tcpSYN(t *testing.T, ts time.Time, src, dst net.IP, port uint16) timedPacket {
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(40000 + port%20000), DstPort: layers.TCPPort(port), SYN: true, Seq: 1000, Window: 64240}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return serializeAt(t, ts, ip, tcp)
}

func dnsPacket(t *testing.T, ts time.Time, src, dst net.IP, id uint16, name string, qtype layers.DNSType, response bool) timedPacket {
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: src, DstIP: dst}
	udp := &layers.UDP{SrcPort: 53000, DstPort: 53}
	if response {
		udp.SrcPort, udp.DstPort = 53, 53000
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	dns := &layers.DNS{ID: id, QR: response, RD: true, Questions: []layers.DNSQuestion{{Name: []byte(name), Type: qtype, Class: layers.DNSClassIN}}}
	return serializeAt(t, ts, ip, udp, dns)
}

func vrrpAdvertisement(t *testing.T, ts time.Time) timedPacket {
	ip := &layers.IPv4{Version: 4, TTL: 255, Protocol: layers.IPProtocolVRRP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(224, 0, 0, 18)}
	// Version 2, advertisement; VRID 7, priority 100, one address, no auth, 1 s.
	body := []byte{0x21, 7, 100, 1, 0, 1, 0, 0, 192, 0, 2, 254, 0, 0, 0, 0, 0, 0, 0, 0}
	var sum uint32
	for i := 0; i < len(body); i += 2 {
		sum += uint32(body[i])<<8 | uint32(body[i+1])
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	checksum := ^uint16(sum)
	body[6], body[7] = byte(checksum>>8), byte(checksum)
	return serializeAt(t, ts, ip, gopacket.Payload(body))
}
