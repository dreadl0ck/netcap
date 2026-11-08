package main

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/networkdetect"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestRound2DetectionDefaultCLI(t *testing.T) {
	if input := os.Getenv("NETCAP_W76_CLI_INPUT"); input != "" {
		os.Args = []string{"net", "capture", "--read", input, "--out", os.Getenv("NETCAP_W76_CLI_OUT"), "--quiet"}
		main()
		return
	}
	root := t.TempDir()
	input, out := filepath.Join(root, "epoch-zero.pcap"), filepath.Join(root, "out")
	f, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.53"), Protocol: layers.IPProtocolUDP}
		udp := &layers.UDP{SrcPort: 40000, DstPort: 53}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		dns := &layers.DNS{ID: uint16(i), RD: true, Questions: []layers.DNSQuestion{{Name: []byte("api.telegram.org"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, dns); err != nil {
			t.Fatal(err)
		}
		data := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(int64(i), 0), CaptureLength: len(data), Length: len(data)}, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRound2DetectionDefaultCLI$", "-test.count=1")
	cmd.Env = append(os.Environ(), "NETCAP_W76_CLI_INPUT="+input, "NETCAP_W76_CLI_OUT="+out)
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("default capture did not exit 0: %v\n%s", err, data)
	}
	r, err := netio.Open(filepath.Join(out, "Alert.ncap.gz"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	var a types.Alert
	if err := r.Next(&a); err != nil {
		t.Fatal(err)
	}
	if a.Name != "policy.telegram-api" || a.Count != 3 || a.FirstSeen != 0 || a.Timestamp != 0 || a.LastSeen != 2e9 || len(a.Examples) != 3 || a.AggregateKey == "" {
		t.Fatal("default CLI lost epoch-zero aggregate", &a)
	}
	if err := r.Next(new(types.Alert)); err != io.EOF {
		t.Fatal("unexpected extra alert", err)
	}
	s, err := networkdetect.ReadStats(filepath.Join(out, networkdetect.StatsFilename))
	if err != nil || s.Events != 3 || s.Matches != 3 || s.Alerts != 1 || s.PendingAggregates != 0 || s.Error != "" {
		t.Fatal(s, err)
	}
}
