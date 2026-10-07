package networkdetect

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func packetForEvent(t *testing.T, ev Event) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP(ev.SrcIP), DstIP: net.ParseIP(ev.DstIP)}
	stack := []gopacket.SerializableLayer{eth, ip}
	switch ev.Kind {
	case "dns":
		ip.Protocol = layers.IPProtocolUDP
		udp := &layers.UDP{SrcPort: 40000, DstPort: 53}
		_ = udp.SetNetworkLayerForChecksum(ip)
		stack = append(stack, udp, &layers.DNS{ID: 1, RD: true, Questions: []layers.DNSQuestion{{Name: []byte(ev.Name), Type: layers.DNSType(ev.QType), Class: layers.DNSClassIN}}})
	case "syn", "data", "end":
		ip.Protocol = layers.IPProtocolTCP
		tcp := &layers.TCP{SrcPort: layers.TCPPort(ev.SrcPort), DstPort: layers.TCPPort(ev.DstPort), Seq: ev.Seq, Window: 65535, SYN: ev.Kind == "syn", ACK: ev.Kind == "data", FIN: ev.Kind == "end"}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		stack = append(stack, tcp, gopacket.Payload(ev.Payload))
	case "icmp":
		ip.Protocol = layers.IPProtocolICMPv4
		stack = append(stack, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: uint16(ev.Seq >> 16), Seq: uint16(ev.Seq)}, gopacket.Payload(ev.Payload))
	default:
		t.Fatal("invalid fixture event")
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, stack...); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestPacketBackedFlightSimContract(t *testing.T) {
	fixture := corpus()
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			e, _ := New(fixture.Config)
			var seen []string
			var file *os.File
			var writer *pcapgo.Writer
			if dir := os.Getenv("NETCAP_NETWORK_FIXTURES"); dir != "" {
				var err error
				file, err = os.Create(filepath.Join(dir, tc.Name+".pcap"))
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				writer = pcapgo.NewWriterNanos(file)
				if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
					t.Fatal(err)
				}
			}
			for _, ev := range tc.Events {
				data := packetForEvent(t, ev)
				packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
				packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(0, ev.At), CaptureLength: len(data), Length: len(data)}
				if writer != nil {
					if err := writer.WritePacket(packet.Metadata().CaptureInfo, data); err != nil {
						t.Fatal(err)
					}
				}
				for _, decoded := range PacketEvents(packet, ev.Scope) {
					alerts, err := e.Observe(decoded)
					if err != nil {
						t.Fatal(err)
					}
					for _, alert := range alerts {
						seen = append(seen, alert.RuleName)
					}
				}
			}
			for _, want := range tc.Expected {
				found := false
				for _, got := range seen {
					found = found || got == want
				}
				if !found {
					t.Fatalf("packet path missing %s: %v", want, seen)
				}
			}
			if len(tc.Expected) == 0 && len(seen) > 0 {
				t.Fatalf("benign packet alerts: %v", seen)
			}
		})
	}
	if dir := os.Getenv("NETCAP_NETWORK_FIXTURES"); dir != "" {
		data, _ := json.MarshalIndent(fixture.Config, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "config.json"), append(data, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
}
