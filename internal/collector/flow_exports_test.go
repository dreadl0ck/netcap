package collector

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/flowexport"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestFlowExportCollectorProcess(t *testing.T) {
	input := os.Getenv("NETCAP_FLOW_EXPORT_INPUT")
	if input == "" {
		return
	}
	workers, err := strconv.Atoi(os.Getenv("NETCAP_FLOW_EXPORT_WORKERS"))
	if err != nil {
		t.Fatal(err)
	}
	c := New(Config{Workers: workers, PacketBufferSize: 8, BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Default, NoSignalHandling: true, NoPrompt: true, FlowExports: true,
		DecoderConfig: &config.Config{Out: os.Getenv("NETCAP_FLOW_EXPORT_OUT"), Quiet: true, IncludeDecoders: "UDP", Proto: true, NoOptCheck: true}})
	if err := c.CollectPcap(input); err != nil {
		t.Fatal(err)
	}
}

func TestFlowExportCollectorWorkerQualification(t *testing.T) {
	input := filepath.Join(t.TempDir(), "exporters.pcap")
	file, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriterNanos(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	shorts := func(values ...uint16) []byte {
		b := make([]byte, len(values)*2)
		for i, n := range values {
			binary.BigEndian.PutUint16(b[i*2:], n)
		}
		return b
	}
	words := func(values ...uint32) []byte {
		b := make([]byte, len(values)*4)
		for i, n := range values {
			binary.BigEndian.PutUint32(b[i*4:], n)
		}
		return b
	}
	makeSet := func(id uint16, body []byte) []byte { return append(shorts(id, uint16(len(body)+4)), body...) }
	packet := func(seq uint32, set []byte) []byte {
		return append(append(shorts(9, 1), words(120000, 1700000000, seq, 7)...), set...)
	}
	templates := [][]byte{shorts(256, 3, 8, 4, 12, 4, 1, 4), shorts(256, 3, 12, 4, 8, 4, 1, 4)}
	data := append(net.IPv4(192, 0, 2, 1).To4(), net.IPv4(198, 51, 100, 1).To4()...)
	data = append(data, words(42)...)
	for exporter := 0; exporter < 2; exporter++ {
		for seq, payload := range [][]byte{packet(0, makeSet(0, templates[exporter])), packet(1, makeSet(256, data))} {
			eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
			ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, byte(10+exporter)), DstIP: net.IPv4(192, 0, 2, 254)}
			udp := &layers.UDP{SrcPort: 50000, DstPort: 2055}
			if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			buffer := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload)); err != nil {
				t.Fatal(err)
			}
			bytes := buffer.Bytes()
			if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(exporter*2+seq)), CaptureLength: len(bytes), Length: len(bytes)}, bytes); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprintf("workers=%d", workers), func(t *testing.T) {
			out := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestFlowExportCollectorProcess$", "-test.count=1")
			command.Env = append(os.Environ(), "NETCAP_FLOW_EXPORT_INPUT="+input, "NETCAP_FLOW_EXPORT_OUT="+out, fmt.Sprintf("NETCAP_FLOW_EXPORT_WORKERS=%d", workers))
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("collector: %v\n%s", err, output)
			}
			file, err := os.Open(filepath.Join(out, "FlowExports.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			sources := map[string]string{}
			for scanner.Scan() {
				var event flowexport.Event
				if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
					t.Fatal(err)
				}
				if event.Kind == "datagram" {
					continue
				}
				if event.Kind != "observation" {
					t.Fatalf("unexpected issue: %+v", event)
				}
				sources[event.Observation.Envelope.Exporter] = event.Observation.SrcIP
				if *event.Observation.Bytes != 42 {
					t.Fatal("counter changed")
				}
			}
			if err := scanner.Err(); err != nil {
				t.Fatal(err)
			}
			if sources["192.0.2.10:50000"] != "192.0.2.1" || sources["192.0.2.11:50000"] != "198.51.100.1" {
				t.Fatalf("templates/order changed with workers: %v", sources)
			}
			data, err := os.ReadFile(filepath.Join(out, "FlowExportsHealth.json"))
			if err != nil {
				t.Fatal(err)
			}
			var health flowexport.RecorderHealth
			if err := json.Unmarshal(data, &health); err != nil {
				t.Fatal(err)
			}
			if health.Status != "done" || health.Datagrams != 4 || health.Records != 2 || health.Malformed != 0 {
				t.Fatalf("health mismatch: %+v", health)
			}
			domain := uint32(7)
			report, err := flowexport.ReadReport(context.Background(), filepath.Join(out, "FlowExports.jsonl"), flowexport.Query{StartNs: 1700000000000000000, EndNs: 1700000000000000004, TimeBasis: "receive", Exporter: "192.0.2.10:50000", Format: "netflow-v9", Domain: &domain, GroupBy: "srcIP", Limit: 10})
			if err != nil {
				t.Fatal(err)
			}
			if report.Excluded != 1 || report.Matched != 0 {
				t.Fatal("record missing packet count was treated as additive")
			}
		})
	}
}
