package collector

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
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
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
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
	t.Helper()
	dc := config.DefaultConfig.Clone()
	dc.Out, dc.Source, dc.IncludeDecoders, dc.Quiet = out, input, "Ethernet,IPv4,TCP,UDP,DNS,ARP,Alert", true
	c := New(Config{Workers: workers, PacketBufferSize: 100, BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Default, DecoderConfig: dc, NoPrompt: true, NoSignalHandling: true, OutDirPermission: 0700})
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
	dir := t.TempDir()
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
			runBehaviorPCAP(t, benign, out, workers, engine)
			if got := replayAlertSemantics(t, out); len(got) != 0 {
				t.Fatalf("benign replay generated alerts: %v", got)
			}
			runBehaviorPCAP(t, attack, out, workers, engine)
			got := replayAlertSemantics(t, out)
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
