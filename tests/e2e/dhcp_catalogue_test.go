//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/devicecatalog"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestDHCPOption55CLI(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	binary := os.Getenv("NETCAP_TEST_BINARY")
	if binary == "" {
		binary = filepath.Join(temp, "net")
		cmd := exec.Command("go", "build", "-tags=nodpi,noyara,nomagika", "-o", binary, "./cmd/net")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOWORK=off")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build CLI: %v\n%s", err, output)
		}
	}
	data, err := os.ReadFile(filepath.Join(root, "internal/devicecatalog/data/dhcp-catalogue-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var catalogue devicecatalog.DHCP
	if err := json.Unmarshal(data, &catalogue); err != nil {
		t.Fatal(err)
	}
	for _, entry := range catalogue.Entries {
		if entry.Key == "1,3,6" {
			catalogue.Entries = []devicecatalog.DHCPEntry{entry}
			break
		}
	}
	if len(catalogue.Entries) != 1 || len(catalogue.Entries[0].Candidates) != 1 {
		t.Fatal("missing unambiguous reviewed fixture")
	}
	label := catalogue.Entries[0].Candidates[0].Label
	data, err = json.Marshal(catalogue)
	if err != nil {
		t.Fatal(err)
	}
	override := filepath.Join(temp, "reviewed-minimal-dhcp.json")
	if err := os.WriteFile(override, data, 0600); err != nil {
		t.Fatal(err)
	}
	pcap := filepath.Join(temp, "option55.pcap")
	file, err := os.Create(pcap)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 17, 34, 51, 68, 85}, DstMAC: net.HardwareAddr{255, 255, 255, 255, 255, 255}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(255, 255, 255, 255), Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 68, DstPort: 67}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	dhcp := &layers.DHCPv4{Operation: layers.DHCPOpRequest, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6, Xid: 1, ClientHWAddr: eth.SrcMAC, Options: layers.DHCPOptions{layers.NewDHCPOption(53, []byte{1}), layers.NewDHCPOption(55, []byte{1, 3, 6})}}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, dhcp); err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, 0), CaptureLength: len(buffer.Bytes()), Length: len(buffer.Bytes())}, buffer.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	for _, admitted := range []bool{false, true} {
		config := filepath.Join(temp, "config")
		if err := os.MkdirAll(filepath.Join(config, "dbs"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(config, "dbs/dhcp-fingerprints.json"), []byte(`{"1,3,6":{"device_name":"stale legacy claim"}}`), 0600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(temp, map[bool]string{false: "missing", true: "admitted"}[admitted])
		cmd := exec.Command(binary, "capture", "-http", "", "-read", pcap, "-out", out, "-include", "Host,DHCPv4", "-dpi=false", "-geoDB=false", "-serviceDB=false", "-macDB=false", "-ja4DB=false", "-quiet")
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, "NC_") {
				cmd.Env = append(cmd.Env, value)
			}
		}
		cmd.Env = append(cmd.Env, "NC_CONFIG_ROOT="+config, "NC_ENRICHMENT_ROOT="+filepath.Join(temp, "absent-channel"))
		if admitted {
			cmd.Env = append(cmd.Env, "NC_DHCP_CATALOGUE="+override)
		}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("capture admitted=%v: %v\n%s", admitted, err, output)
		}
		reader, err := netio.Open(filepath.Join(out, "Host.ncap.gz"), defaults.BufferSize)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reader.ReadHeader(); err != nil {
			t.Fatal(err)
		}
		found := false
		for {
			var host types.Host
			if err := reader.Next(&host); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(host.Devices, "stale legacy claim") {
				t.Fatal("legacy catalogue activated")
			}
			if host.Addr == "192.0.2.1" {
				found = slices.Contains(host.Devices, label)
			}
		}
		reader.Close()
		if found != admitted {
			t.Fatalf("option-55 label admitted=%v, found=%v", admitted, found)
		}
	}
}
