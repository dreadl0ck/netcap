package firewallaudit

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/collector"
	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/tcp"
	"github.com/dreadl0ck/netcap/internal/filter"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/expr-lang/expr"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestCollectorFixtureObserverWithNullSink(t *testing.T) {
	tcp.ResetStreamFactory()
	defer tcp.ResetStreamFactory()
	input := filepath.Join("..", "..", "tests", "The Ultimate PCAP v20260316.pcapng")
	b := policy.Bundle{Version: "1", ID: "pcap", Mode: "enforce", Default: "allow"}
	fields := map[string]string{"SMB": "Version", "TLSClientHello": "Version", "SMTP": "IsEncrypted", "DNS": "ID", "Modbus": "FunctionCode"}
	for name, field := range fields {
		b.Rules = append(b.Rules, policy.Rule{ID: name, Action: "deny", Expression: fmt.Sprintf("Protocol == 'audit' && RecordType == '%s' && Fields['%s'] != ''", name, field)})
	}
	r, err := Open(Config{PolicyFile: writeJSON(t, "pcap.json", b)})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	legacy, err := filter.CompileExpression("FunctionCode >= 0", types.Type_NC_Modbus)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seen := map[string]int{}
	previous := 0
	legacyMatches := 0
	observer := r.Chain(func(m proto.Message) {
		mu.Lock()
		defer mu.Unlock()
		previous++
		if record, ok := m.(*types.Modbus); ok {
			value, err := expr.Run(legacy, filter.CreateEnvironment(record))
			if err != nil || value != true {
				t.Errorf("legacy direct-field expression: %v %v", value, err)
			} else {
				legacyMatches++
			}
		}
	})
	dc := config.DefaultConfig.Clone()
	dc.Out, dc.Source, dc.IncludeDecoders, dc.Quiet = t.TempDir(), input, "SMB,TLSClientHello,SMTP,DNS,Modbus,Alert", true
	dc.Null = true
	dc.AllowMissingInit, dc.NoOptCheck, dc.IgnoreFSMerr = true, true, true
	dc.NumStreamWorkers = 1
	observe := func(m proto.Message) {
		observer(m)
		result := r.Observe(m, nil)
		if result.Reason == "evaluation-failed" || result.Reason == "projection-failed" {
			t.Errorf("record evaluation: %+v", result)
		}
		if result.Decision.RuleID != "" {
			mu.Lock()
			seen[result.RecordType]++
			mu.Unlock()
		}
	}
	dc.RecordObserver = observe
	oldDB := resolvers.DataBaseFolderPath
	resolvers.DataBaseFolderPath = t.TempDir()
	defer func() { resolvers.DataBaseFolderPath = oldDB }()
	c := collector.New(collector.Config{Workers: 2, PacketBufferSize: 100, ReassembleConnections: true, NoPrompt: true, NoSignalHandling: true, BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Default, DecoderConfig: dc, NetworkDetection: true})
	if err = Prepare(c); err != nil {
		t.Fatal(err)
	}
	if err = Prepare(c); err != nil {
		t.Fatal(err)
	} // preparation must not double-observe
	if err = c.CollectPcapNG(input); err != nil {
		t.Fatal(err)
	}
	if err = c.GetNetworkDetectionError(); err != nil {
		t.Fatal(err)
	}
	// The mixed real capture has SMB/TLS/SMTP/DNS but no Modbus. Exercise
	// Modbus through a wire-level TCP fixture rather than inventing a record.
	tcp.ResetStreamFactory()
	dc = dc.Clone()
	dc.RecordObserver = observe
	dc.Out, dc.Source, dc.IncludeDecoders = t.TempDir(), modbusPCAP(t), "Modbus,Alert"
	c = collector.New(collector.Config{Workers: 1, PacketBufferSize: 100, ReassembleConnections: true, NoPrompt: true, NoSignalHandling: true, BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Default, DecoderConfig: dc, NetworkDetection: true})
	if err = Prepare(c); err != nil {
		t.Fatal(err)
	}
	if err = c.CollectPcap(dc.Source); err != nil {
		t.Fatal(err)
	}
	if err = c.GetNetworkDetectionError(); err != nil {
		t.Fatal(err)
	}
	for name := range fields {
		if seen[name] == 0 {
			t.Errorf("real PCAP had no field predicate match for %s", name)
		}
	}
	if previous == 0 || legacyMatches == 0 {
		t.Fatal("existing observer/direct-field detection lost")
	}
	t.Logf("null-sink PCAP predicate matches: %v; previous observer=%d; legacy Modbus matches=%d", seen, previous, legacyMatches)
}

func modbusPCAP(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "modbus.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err = w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	write := func(reverse bool, tcp layers.TCP, payload []byte) {
		a, b := "192.0.2.5", "198.51.100.7"
		if reverse {
			a, b = b, a
		}
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(a), DstIP: net.ParseIP(b)}
		tcp.Window = 65535
		if err = tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		buf := gopacket.NewSerializeBuffer()
		if err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, &tcp, gopacket.Payload(payload)); err != nil {
			t.Fatal(err)
		}
		data := buf.Bytes()
		if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, 0), CaptureLength: len(data), Length: len(data)}, data); err != nil {
			t.Fatal(err)
		}
	}
	write(false, layers.TCP{SrcPort: 40000, DstPort: 502, Seq: 1000, SYN: true}, nil)
	write(true, layers.TCP{SrcPort: 502, DstPort: 40000, Seq: 2000, Ack: 1001, SYN: true, ACK: true}, nil)
	write(false, layers.TCP{SrcPort: 40000, DstPort: 502, Seq: 1001, Ack: 2001, ACK: true}, nil)
	adu := []byte{0, 1, 0, 0, 0, 6, 1, 6, 0, 42, 0, 1}
	write(false, layers.TCP{SrcPort: 40000, DstPort: 502, Seq: 1001, Ack: 2001, ACK: true, PSH: true}, adu)
	write(true, layers.TCP{SrcPort: 502, DstPort: 40000, Seq: 2001, Ack: 1013, ACK: true, PSH: true}, adu)
	return path
}
