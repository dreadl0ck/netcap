package collector

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/internal/testutil"
	"github.com/dreadl0ck/netcap/types"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"go.uber.org/zap"
)

type behaviorPacket struct {
	at    time.Time
	stack []gopacket.SerializableLayer
}

func replaySYN(at time.Time, src, dst string, port uint16, seq uint32) behaviorPacket {
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst), Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(50000 + seq), DstPort: layers.TCPPort(port), SYN: true, Seq: seq}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
	return behaviorPacket{at: at, stack: []gopacket.SerializableLayer{eth, ip, tcp}}
}

func replayARP(at time.Time, ip string, mac byte) behaviorPacket {
	hardware := net.HardwareAddr{0, 1, 2, 3, 4, mac}
	return behaviorPacket{at: at, stack: []gopacket.SerializableLayer{
		&layers.Ethernet{SrcMAC: hardware, DstMAC: net.HardwareAddr{255, 255, 255, 255, 255, 255}, EthernetType: layers.EthernetTypeARP},
		&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPReply, SourceHwAddress: hardware, SourceProtAddress: net.ParseIP(ip).To4(), DstHwAddress: make([]byte, 6), DstProtAddress: net.ParseIP("192.0.2.1").To4()},
	}}
}

func replayDNS(at time.Time, resolver, domain string) behaviorPacket {
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP("192.0.2.10"), DstIP: net.ParseIP(resolver), Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 53000, DstPort: 53}
	_ = udp.SetNetworkLayerForChecksum(ip)
	return behaviorPacket{at: at, stack: []gopacket.SerializableLayer{
		&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}, ip, udp,
		&layers.DNS{ID: 1, RD: true, Questions: []layers.DNSQuestion{{Name: []byte(domain), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}},
	}}
}

func replayDHCP(at time.Time, mac byte) behaviorPacket {
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("255.255.255.255"), Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 67, DstPort: 68}
	_ = udp.SetNetworkLayerForChecksum(ip)
	return behaviorPacket{at: at, stack: []gopacket.SerializableLayer{
		&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 1}, DstMAC: net.HardwareAddr{255, 255, 255, 255, 255, 255}, EthernetType: layers.EthernetTypeIPv4}, ip, udp,
		&layers.DHCPv4{Operation: layers.DHCPOpReply, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6, YourClientIP: net.ParseIP("192.0.2.130"), ClientHWAddr: net.HardwareAddr{0, 1, 2, 3, 4, mac}, Options: layers.DHCPOptions{
			{Type: layers.DHCPOptMessageType, Length: 1, Data: []byte{byte(layers.DHCPMsgTypeAck)}},
			{Type: layers.DHCPOptSubnetMask, Length: 4, Data: []byte{255, 255, 255, 128}},
			{Type: layers.DHCPOptLeaseTime, Length: 4, Data: []byte{0, 0, 14, 16}},
		}},
	}}
}

func replayNDP(at time.Time, mac byte) behaviorPacket {
	ip := &layers.IPv6{Version: 6, HopLimit: 255, SrcIP: net.ParseIP("2001:db8:1::10"), DstIP: net.ParseIP("ff02::1"), NextHeader: layers.IPProtocolICMPv6}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0)}
	_ = icmp.SetNetworkLayerForChecksum(ip)
	return behaviorPacket{at: at, stack: []gopacket.SerializableLayer{
		&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, mac}, DstMAC: net.HardwareAddr{0x33, 0x33, 0, 0, 0, 1}, EthernetType: layers.EthernetTypeIPv6}, ip, icmp,
		&layers.ICMPv6NeighborAdvertisement{TargetAddress: ip.SrcIP, Options: layers.ICMPv6Options{{Type: layers.ICMPv6OptTargetAddress, Data: []byte{0, 1, 2, 3, 4, mac}}}},
	}}
}

func TestBehavioralAddressChangesPCAPOracle(t *testing.T) {
	start := time.Unix(1700000000, 0)
	root := behaviorFixtureDirectory(t, "address-changes")
	training, benign, reassignment, attack := filepath.Join(root, "training.pcap"), filepath.Join(root, "benign.pcap"), filepath.Join(root, "reassignment.pcap"), filepath.Join(root, "attack.pcap")
	writeBehaviorPCAP(t, training, []behaviorPacket{replayDHCP(start, 5), replayNDP(start.Add(2*time.Second), 5)})
	writeBehaviorPCAP(t, benign, []behaviorPacket{replayARP(start.Add(3*time.Second), "192.0.2.130", 5), replayNDP(start.Add(4*time.Second), 5)})
	writeBehaviorPCAP(t, reassignment, []behaviorPacket{replayDHCP(start.Add(5*time.Second), 9), replayARP(start.Add(6*time.Second), "192.0.2.130", 9)})
	writeBehaviorPCAP(t, attack, []behaviorPacket{replayARP(start.Add(7*time.Second), "192.0.2.130", 5), replayNDP(start.Add(8*time.Second), 7)})
	var reference []string
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := t.TempDir()
			sink, err := rules.NewFileAlertWriter(out)
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			engine, err := behavior.Open(behavior.Config{Path: filepath.Join(out, "Behavior.json"), MinLearning: time.Second, MinSamples: 2}, sink)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			runBehaviorPCAP(t, training, out, workers, engine)
			if err := engine.Change("approve", nil, "reviewed address fixture"); err != nil {
				t.Fatal(err)
			}
			if workers == 1 {
				exportBehaviorSeed(t, root, engine)
			}
			runBehaviorPCAP(t, benign, out, workers, engine)
			if got := replayAlertSemantics(t, out); len(got) != 0 {
				t.Fatalf("benign address traffic generated alerts: %v", got)
			}
			runBehaviorPCAP(t, reassignment, out, workers, engine)
			for _, item := range replayAlertSemantics(t, out) {
				if strings.HasPrefix(item, "baseline.arp-conflict|") {
					t.Fatal("approved DHCP transition was classified as spoofing")
				}
			}
			runBehaviorPCAP(t, attack, out, workers, engine)
			got := replayAlertSemantics(t, out)
			if workers == 1 {
				exportBehaviorResult(t, root, got, false, benign, reassignment, attack)
			}
			oracle := map[string]int{"baseline.new-device": 2, "baseline.dhcp-reassignment": 1, "baseline.arp-conflict": 1, "baseline.address-conflict": 1}
			for _, item := range got {
				name, _, _ := strings.Cut(item, "|")
				if _, exists := oracle[name]; !exists {
					t.Fatalf("unexpected address detector %s", name)
				}
				oracle[name]--
			}
			for name, remaining := range oracle {
				if remaining != 0 {
					t.Fatalf("address detector %s differs by %d", name, remaining)
				}
			}
			if reference == nil {
				reference = got
			} else if !reflect.DeepEqual(reference, got) {
				t.Fatal("worker count changed address evidence")
			}
		})
	}
}

func TestBehavioralDiscoveryAndDNSPCAPOracle(t *testing.T) {
	start := time.Unix(1700000000, 0)
	root := behaviorFixtureDirectory(t, "discovery-dns")
	training, benign, attack := filepath.Join(root, "training.pcap"), filepath.Join(root, "benign.pcap"), filepath.Join(root, "attack.pcap")
	writeBehaviorPCAP(t, training, []behaviorPacket{replayARP(start, "192.0.2.10", 5), replayDNS(start.Add(2*time.Second), "192.0.2.53", "known.example")})
	writeBehaviorPCAP(t, benign, []behaviorPacket{replayARP(start.Add(3*time.Second), "192.0.2.10", 5), replayDNS(start.Add(4*time.Second), "192.0.2.53", "known.example")})
	writeBehaviorPCAP(t, attack, []behaviorPacket{replayARP(start.Add(5*time.Second), "192.0.2.10", 9), replayDNS(start.Add(6*time.Second), "192.0.2.54", "novel.example"), replaySYN(start.Add(7*time.Second), "192.0.2.10", "192.0.2.20", 8443, 1)})
	var reference []string
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := t.TempDir()
			sink, err := rules.NewFileAlertWriter(out)
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			engine, err := behavior.Open(behavior.Config{Path: filepath.Join(out, "Behavior.json"), MinLearning: time.Second, MinSamples: 2}, sink)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			runBehaviorPCAP(t, training, out, workers, engine)
			if err := engine.Change("approve", nil, "reviewed discovery fixture"); err != nil {
				t.Fatal(err)
			}
			if workers == 1 {
				exportBehaviorSeed(t, root, engine)
			}
			runBehaviorPCAP(t, benign, out, workers, engine)
			if got := replayAlertSemantics(t, out); len(got) != 0 {
				t.Fatalf("benign discovery generated alerts: %v", got)
			}
			runBehaviorPCAP(t, attack, out, workers, engine)
			got := replayAlertSemantics(t, out)
			if workers == 1 {
				exportBehaviorResult(t, root, got, false, benign, attack)
			}
			oracle := map[string]int{"baseline.new-device": 1, "baseline.arp-conflict": 1, "baseline.new-resolver": 1, "baseline.new-dns": 1, "baseline.new-edge": 2, "baseline.new-service": 1}
			for _, item := range got {
				name, _, _ := strings.Cut(item, "|")
				if _, exists := oracle[name]; !exists {
					t.Fatalf("unexpected detector: %s", name)
				}
				oracle[name]--
			}
			for name, remaining := range oracle {
				if remaining != 0 {
					t.Fatalf("detector %s differs from oracle by %d", name, remaining)
				}
			}
			if reference == nil {
				reference = got
			} else if !reflect.DeepEqual(reference, got) {
				t.Fatal("worker count changed discovery evidence")
			}
		})
	}
}

func writeBehaviorPCAP(t *testing.T, path string, packets []behaviorPacket) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for _, packet := range packets {
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, packet.stack...); err != nil {
			t.Fatal(err)
		}
		data := buffer.Bytes()
		if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: packet.at, CaptureLength: len(data), Length: len(data)}, data); err != nil {
			t.Fatal(err)
		}
	}
}

func runBehaviorPCAP(t *testing.T, input, out string, workers int, engine *behavior.Engine) {
	runBehaviorPCAPWithResolvers(t, input, out, workers, engine, resolvers.Config{})
}

func runBehaviorPCAPWithResolvers(t *testing.T, input, out string, workers int, engine *behavior.Engine, rc resolvers.Config) {
	t.Helper()
	dc := config.DefaultConfig.Clone()
	dc.Out, dc.Source, dc.IncludeDecoders, dc.Quiet = out, input, "Ethernet,IPv4,TCP,UDP,DNS,ARP,Alert", true
	c := New(Config{Workers: workers, PacketBufferSize: 100, BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Default, DecoderConfig: dc, ResolverConfig: rc, NoPrompt: true, NoSignalHandling: true, OutDirPermission: 0700})
	c.SetBehaviorEngine(engine, behavior.Scope{Sensor: "replay", Interface: "pcap"})
	if err := c.CollectPcap(input); err != nil {
		t.Fatal(err)
	}
	if err := c.GetBehaviorError(); err != nil {
		t.Fatal(err)
	}
}

func replayAlertSemantics(t *testing.T, out string) []string {
	t.Helper()
	r, err := netio.Open(filepath.Join(out, "Alert.ncap.gz"), 4096)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	var result []string
	for {
		var alert types.Alert
		if err := r.Next(&alert); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		result = append(result, fmt.Sprintf("%s|%s|%s|%s", alert.RuleName, alert.SrcIP, alert.DstIP, alert.MatchedRecord))
	}
	sort.Strings(result)
	return result
}

func TestBehavioralPCAPReplayAcrossWorkerCounts(t *testing.T) {
	start := time.Unix(1700000000, 0)
	dir := behaviorFixtureDirectory(t, "lateral")
	training, attack, benign := filepath.Join(dir, "training.pcap"), filepath.Join(dir, "attack.pcap"), filepath.Join(dir, "benign.pcap")
	writeBehaviorPCAP(t, training, []behaviorPacket{replaySYN(start, "192.0.2.10", "192.0.2.20", 443, 1), replaySYN(start.Add(2*time.Second), "192.0.2.10", "192.0.2.20", 443, 2)})
	var packets []behaviorPacket
	for i := range 5 {
		packets = append(packets, replaySYN(start.Add(time.Duration(i+10)*time.Second), "192.0.2.10", fmt.Sprintf("192.0.2.%d", i+30), 445, uint32(i+3)))
	}
	for i := range 10 {
		packets = append(packets, replaySYN(start.Add(time.Duration(i+20)*time.Second), "192.0.2.10", "192.0.2.20", 3389, uint32(i+10)))
	}
	packets = append(packets, replaySYN(start.Add(40*time.Second), "192.0.2.10", "192.0.2.20", 22, 25), replaySYN(start.Add(41*time.Second), "192.0.2.20", "192.0.2.40", 22, 26))
	writeBehaviorPCAP(t, attack, packets)
	writeBehaviorPCAP(t, benign, []behaviorPacket{replaySYN(start.Add(10*time.Second), "192.0.2.10", "192.0.2.20", 443, 5), replaySYN(start.Add(11*time.Second), "192.0.2.10", "192.0.2.20", 443, 5)})
	var reference []string
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := t.TempDir()
			sink, err := rules.NewFileAlertWriter(out)
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			engine, err := behavior.Open(behavior.Config{Path: filepath.Join(out, "Behavior.json"), MinLearning: time.Second, MinSamples: 2}, sink)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			if err := engine.AddPrefix(behavior.Scope{Sensor: "replay", Interface: "pcap"}, "192.0.2.0/24", "configured"); err != nil {
				t.Fatal(err)
			}
			runBehaviorPCAP(t, training, out, workers, engine)
			if err := engine.Change("approve", nil, "reviewed replay fixture"); err != nil {
				t.Fatal(err)
			}
			if workers == 1 {
				exportBehaviorSeed(t, dir, engine)
			}
			runBehaviorPCAP(t, benign, out, workers, engine)
			if got := replayAlertSemantics(t, out); len(got) != 0 {
				t.Fatalf("benign replay generated alerts: %v", got)
			}
			runBehaviorPCAP(t, attack, out, workers, engine)
			got := replayAlertSemantics(t, out)
			if workers == 1 {
				exportBehaviorResult(t, dir, got, false, benign, attack)
			}
			if len(got) == 0 {
				t.Fatal("attack fixture produced no alerts")
			}
			oracle := map[string]int{"lateral.smb-fanout": 1, "lateral.rdp-attempts": 1, "lateral.new-ssh-edge": 2, "lateral.pivot-sequence": 1}
			for _, item := range got {
				name, _, _ := strings.Cut(item, "|")
				if _, required := oracle[name]; required {
					oracle[name]--
				}
			}
			for name, remaining := range oracle {
				if remaining != 0 {
					t.Fatalf("fixture detector %s count differs from oracle by %d", name, remaining)
				}
			}
			if reference == nil {
				reference = got
			} else if !reflect.DeepEqual(reference, got) {
				t.Fatal("worker count changed behavioral evidence")
			}
		})
	}
}

func TestBehavioralRatePCAPOracle(t *testing.T) {
	start := time.Unix(1700000000, 0)
	root := behaviorFixtureDirectory(t, "rates")
	training, benign, attack := filepath.Join(root, "training.pcap"), filepath.Join(root, "benign.pcap"), filepath.Join(root, "attack.pcap")
	var packets []behaviorPacket
	for window := range 5 {
		for i := range 10 {
			packets = append(packets, replaySYN(start.Add(time.Duration(window)*time.Second), "192.0.2.10", "192.0.2.20", 443, uint32(window*10+i+1)))
		}
	}
	writeBehaviorPCAP(t, training, packets)
	packets = nil
	for i := range 10 {
		packets = append(packets, replaySYN(start.Add(5*time.Second), "192.0.2.10", "192.0.2.20", 443, uint32(i+100)))
	}
	writeBehaviorPCAP(t, benign, packets)
	packets = nil
	for i := range 101 {
		packet := replaySYN(start.Add(6*time.Second), "192.0.2.10", "192.0.2.20", 443, uint32(i+200))
		packet.stack = append(packet.stack, gopacket.Payload(make([]byte, 16000)))
		packets = append(packets, packet)
	}
	writeBehaviorPCAP(t, attack, packets)
	var reference []string
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := t.TempDir()
			sink, err := rules.NewFileAlertWriter(out)
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			policy := behavior.DefaultPolicy()
			policy.WindowNS = int64(time.Second)
			engine, err := behavior.Open(behavior.Config{Path: filepath.Join(out, "Behavior.json"), MinLearning: time.Second, MinSamples: 2, Policy: &policy}, sink)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			runBehaviorPCAP(t, training, out, workers, engine)
			if err := engine.Change("approve", nil, "reviewed rate fixture"); err != nil {
				t.Fatal(err)
			}
			if workers == 1 {
				exportBehaviorSeed(t, root, engine)
			}
			before := engine.Snapshot()
			runBehaviorPCAP(t, benign, out, workers, engine)
			if got := replayAlertSemantics(t, out); len(got) != 0 {
				t.Fatalf("benign rate generated alerts: %v", got)
			}
			runBehaviorPCAP(t, attack, out, workers, engine)
			got := replayAlertSemantics(t, out)
			if workers == 1 {
				exportBehaviorResult(t, root, got, false, benign, attack)
			}
			oracle := map[string]int{"baseline.packet-rate": 1, "baseline.byte-rate": 1}
			for _, item := range got {
				name, _, _ := strings.Cut(item, "|")
				if _, exists := oracle[name]; !exists {
					t.Fatalf("unexpected rate detector %s", name)
				}
				oracle[name]--
			}
			for name, remaining := range oracle {
				if remaining != 0 {
					t.Fatalf("rate detector %s differs by %d", name, remaining)
				}
			}
			after := engine.Snapshot()
			if !reflect.DeepEqual(before.ApprovedRates, after.ApprovedRates) || before.BaselineID != after.BaselineID {
				t.Fatal("monitoring changed frozen rate baseline")
			}
			if reference == nil {
				reference = got
			} else if !reflect.DeepEqual(reference, got) {
				t.Fatal("worker count changed rate evidence")
			}
		})
	}
}

func TestBehavioralGeographicPCAPOracle(t *testing.T) {
	root := behaviorFixtureDirectory(t, "geography")
	dbs := filepath.Join(root, "dbs")
	if err := os.MkdirAll(dbs, 0700); err != nil {
		t.Fatal(err)
	}
	oldPath, oldRoot, oldConfig := resolvers.DataBaseFolderPath, resolvers.ConfigRootPath, resolvers.CurrentConfig
	resolvers.DataBaseFolderPath, resolvers.ConfigRootPath = dbs, root
	t.Setenv("NC_GEO_PROVIDERS", "dbip")
	t.Cleanup(func() {
		resolvers.SetLogger(zap.NewNop())
		resolvers.Init(resolvers.Config{}, true)
		resolvers.DataBaseFolderPath, resolvers.ConfigRootPath, resolvers.CurrentConfig = oldPath, oldRoot, oldConfig
	})
	files := resolvers.GeoFiles("dbip")
	testutil.WriteMMDB(t, filepath.Join(dbs, files.City), "DBIP-City-Lite", time.Unix(1700000000, 0), map[string]mmdbtype.Map{"1.1.1.0/24": testutil.City("AU", "fixture"), "8.8.8.0/24": testutil.City("US", "fixture")})
	testutil.WriteMMDB(t, filepath.Join(dbs, files.ASN), "DBIP-ASN-Lite (compat=GeoLite2-ASN)", time.Unix(1700000000, 0), map[string]mmdbtype.Map{"1.1.1.0/24": testutil.ASN(13335, "fixture"), "8.8.8.0/24": testutil.ASN(15169, "fixture")})
	start := time.Unix(1700000000, 0)
	training, benign, attack := filepath.Join(root, "training.pcap"), filepath.Join(root, "benign.pcap"), filepath.Join(root, "attack.pcap")
	writeBehaviorPCAP(t, training, []behaviorPacket{replaySYN(start, "192.0.2.10", "1.1.1.1", 443, 1), replaySYN(start.Add(time.Second), "192.0.2.10", "1.1.1.1", 443, 2), replaySYN(start.Add(2*time.Second), "192.0.2.10", "10.0.0.1", 443, 3)})
	writeBehaviorPCAP(t, benign, []behaviorPacket{replaySYN(start.Add(3*time.Second), "192.0.2.10", "1.1.1.1", 443, 4), replaySYN(start.Add(4*time.Second), "192.0.2.10", "10.0.0.1", 443, 5)})
	writeBehaviorPCAP(t, attack, []behaviorPacket{replaySYN(start.Add(5*time.Second), "192.0.2.10", "8.8.8.8", 443, 6)})
	var reference []string
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := t.TempDir()
			sink, err := rules.NewFileAlertWriter(out)
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			policy := behavior.DefaultPolicy()
			policy.DeniedCountries, policy.DeniedASNs = []string{"US"}, []string{"15169"}
			engine, err := behavior.Open(behavior.Config{Path: filepath.Join(out, "Behavior.json"), MinLearning: time.Second, MinSamples: 2, Policy: &policy}, sink)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			run := func(input string) {
				runBehaviorPCAPWithResolvers(t, input, out, workers, engine, resolvers.Config{GeolocationDB: true, GeoProviders: "dbip"})
			}
			run(training)
			if err := engine.Change("approve", nil, "reviewed geographic fixture"); err != nil {
				t.Fatal(err)
			}
			if workers == 1 {
				exportBehaviorSeed(t, root, engine)
			}
			run(benign)
			if got := replayAlertSemantics(t, out); len(got) != 0 {
				t.Fatalf("benign geography generated alerts: %v", got)
			}
			run(attack)
			got := replayAlertSemantics(t, out)
			if workers == 1 {
				exportBehaviorResult(t, root, got, true, benign, attack)
			}
			oracle := map[string]int{"baseline.new-geo": 1, "policy.geographic-country": 1, "policy.geographic-asn": 1, "baseline.new-edge": 1, "baseline.new-service": 1}
			for _, item := range got {
				name, _, _ := strings.Cut(item, "|")
				if _, exists := oracle[name]; !exists {
					t.Fatalf("unexpected geographic detector %s", name)
				}
				oracle[name]--
			}
			for name, remaining := range oracle {
				if remaining != 0 {
					t.Fatalf("geographic detector %s differs by %d", name, remaining)
				}
			}
			for _, observation := range engine.Snapshot().Observed {
				if observation.Fact.Kind == "geo" && (observation.Fact.DstIP == "10.0.0.1" || observation.Fact.Provenance != "dbip") {
					t.Fatal("private address acquired geolocation or provider provenance was lost")
				}
			}
			if reference == nil {
				reference = got
			} else if !reflect.DeepEqual(reference, got) {
				t.Fatal("worker count changed geographic evidence")
			}
		})
	}
}

func TestBehavioralCollectorPressure(t *testing.T) {
	if os.Getenv("NETCAP_BEHAVIOR_PRESSURE") != "1" {
		t.Skip("100,000-packet capture qualification; enable NETCAP_BEHAVIOR_PRESSURE=1")
	}
	const count = 100000
	start := time.Unix(1700000000, 0)
	root := t.TempDir()
	input, out := filepath.Join(root, "pressure.pcap"), filepath.Join(root, "audit")
	packet := replaySYN(start, "192.0.2.10", "192.0.2.20", 443, 1)
	packets := make([]behaviorPacket, count)
	for i := range packets {
		packets[i] = behaviorPacket{at: start.Add(2*time.Second + time.Duration(i)*100*time.Microsecond), stack: packet.stack}
	}
	writeBehaviorPCAP(t, input, packets)
	sink, err := rules.NewFileAlertWriter(out)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	engine, err := behavior.Open(behavior.Config{Path: filepath.Join(out, "Behavior.json"), MinLearning: time.Second, MinSamples: 2, MaxFacts: 1000}, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, packet.stack...); err != nil {
		t.Fatal(err)
	}
	facts := behavior.PacketFacts(gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default), behavior.Scope{Sensor: "pressure", Interface: "pcap"})
	for _, at := range []time.Time{start, start.Add(time.Second)} {
		if err := engine.Observe(at, facts...); err != nil {
			t.Fatal(err)
		}
	}
	if err := engine.Change("approve", nil, "reviewed pressure fixture"); err != nil {
		t.Fatal(err)
	}
	dc := config.DefaultConfig.Clone()
	dc.Out, dc.Source, dc.IncludeDecoders, dc.Quiet = out, input, "Ethernet,IPv4,TCP,Alert", true
	c := New(Config{Workers: 4, PacketBufferSize: 100, BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Default, DecoderConfig: dc, NoPrompt: true, NoSignalHandling: true, OutDirPermission: 0700})
	c.SetBehaviorEngine(engine, behavior.Scope{Sensor: "pressure", Interface: "pcap"})
	received := time.Now()
	if err := c.CollectPcap(input); err != nil {
		t.Fatal(err)
	}
	duration := time.Since(received)
	if err := c.GetBehaviorError(); err != nil {
		t.Fatal(err)
	}
	state := engine.Snapshot()
	if c.GetCurrentPacketCount() != count || state.Samples != count+2 {
		t.Fatalf("ingress lost packets: collector=%d observations=%d", c.GetCurrentPacketCount(), state.Samples)
	}
	if state.Overflow != 0 || state.WindowOverflow != 0 || len(state.Observed) != 3 || len(state.Activity) > state.MaxFacts || len(state.Rates) > state.MaxFacts {
		t.Fatalf("state bounds under pressure: %+v", state)
	}
	if got := replayAlertSemantics(t, out); len(got) != 0 {
		t.Fatalf("stable pressure traffic produced false alerts: %v", got)
	}
	t.Logf("OS=%s arch=%s CPUs=%d Go=%s packets=%d workers=4 packetBuffer=100 sensors=1 approvedFacts=3 maxFacts=1000 decoders=Ethernet,IPv4,TCP,Alert behavioralPolicy=default wall=%s throughput=%.0f packets/s missingIngress=0 factOverflow=0 windowOverflow=0; offline PCAP has no kernel-capture drops; includes protocol audit persistence and capture shutdown", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version(), count, duration, count/duration.Seconds())
}
