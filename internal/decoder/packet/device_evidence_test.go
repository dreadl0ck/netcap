package packet

import (
	"bytes"
	decoderutils "github.com/dreadl0ck/netcap/internal/decoder/utils"
	"github.com/dreadl0ck/netcap/internal/dpi"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"net"
	"testing"
)

func TestGatewayDoesNotOwnRoutedSources(t *testing.T) {
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	b := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{SrcMAC: mac, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, TTL: 63, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(203, 0, 113, 9), DstIP: net.IPv4(192, 0, 2, 1)},
		&layers.UDP{SrcPort: 443, DstPort: 12345}); err != nil {
		t.Fatal(err)
	}
	i := decoderutils.NewPacketInfo(gopacket.NewPacket(b.Bytes(), layers.LayerTypeEthernet, gopacket.Default))
	p := newDeviceProfile(i)
	applyDeviceProfileUpdate(p, i)
	if len(p.DeviceIPs) != 0 {
		t.Fatal("routed address attributed to next-hop", p.DeviceIPs)
	}
	if !dpi.IsEnabled() && len(p.streamBuffers) != 0 {
		t.Fatal("nodpi retained packet copies")
	}
	addDeviceIP(p, net.IPv4(192, 0, 2, 254))
	addDeviceIP(p, net.IPv4zero)
	if len(p.DeviceIPs) != 1 || p.DeviceIPs[0] != "192.0.2.254" {
		t.Fatal(p.DeviceIPs)
	}
}

func TestDHCPPaddingAndOptionOverload(t *testing.T) {
	d := &layers.DHCPv4{ServerName: append([]byte("server"), make([]byte, 58)...), File: make([]byte, 128)}
	name, file := dhcpTextFields(d)
	if string(name) != "server" || len(file) != 0 {
		t.Fatal(name, file)
	}
	d.Options = []layers.DHCPOption{{Type: 52, Data: []byte{3}}}
	name, file = dhcpTextFields(d)
	if !bytes.Equal(name, d.ServerName) || !bytes.Equal(file, d.File) {
		t.Fatal("overloaded options were trimmed")
	}
}
