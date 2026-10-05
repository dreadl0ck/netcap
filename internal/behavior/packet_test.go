package behavior

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func serializePacket(t *testing.T, stack ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, stack...); err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	if err := packet.ErrorLayer(); err != nil {
		t.Fatalf("packet decode: %v", err.Error())
	}
	packet.Metadata().CaptureInfo.Timestamp = testTime
	return packet
}

func ethernet() *layers.Ethernet {
	return &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
}

func TestPacketFactsSYNAndVLAN(t *testing.T) {
	scope := testFact().Scope
	eth := ethernet()
	eth.EthernetType = layers.EthernetTypeDot1Q
	vlan := &layers.Dot1Q{VLANIdentifier: 20, Type: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 55000, DstPort: 22, SYN: true}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	facts := PacketFacts(serializePacket(t, eth, vlan, ip, tcp), scope)
	if len(facts) != 2 || facts[1].Kind != "service" || facts[1].Port != 22 || len(facts[1].Scope.VLANs) != 1 || facts[1].Scope.VLANs[0] != 20 {
		t.Fatalf("facts = %+v", facts)
	}
	for _, fact := range facts {
		if fact.Kind == "device" {
			t.Fatal("routed IP traffic was assigned the next-hop MAC")
		}
	}
	tcp.SYN, tcp.ACK = false, true
	tcp.SrcPort, tcp.DstPort = 22, 55000
	ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
	reply := PacketFacts(serializePacket(t, eth, vlan, ip, tcp), scope)
	if len(reply) != 1 || factID(reply[0]) != factID(facts[0]) {
		t.Fatalf("reply creates service or new edge: %+v", reply)
	}
}

func TestPacketFactsARP(t *testing.T) {
	eth := ethernet()
	eth.EthernetType = layers.EthernetTypeARP
	arp := &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: 2,
		SourceHwAddress: []byte{0, 1, 2, 3, 4, 5}, SourceProtAddress: []byte{192, 0, 2, 1}, DstHwAddress: []byte{0, 1, 2, 3, 4, 6}, DstProtAddress: []byte{192, 0, 2, 2}}
	facts := PacketFacts(serializePacket(t, eth, arp), testFact().Scope)
	if len(facts) != 2 || facts[0].Kind != "device" || facts[1].Kind != "binding" || facts[1].SrcIP != "192.0.2.1" {
		t.Fatalf("facts = %+v", facts)
	}
	arp.SourceProtAddress = []byte{0, 0, 0, 0}
	if got := PacketFacts(serializePacket(t, eth, arp), testFact().Scope); len(got) != 0 {
		t.Fatal("ARP probe became an assigned binding")
	}
}

func TestPacketFactsDNSQueriesOnly(t *testing.T) {
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.53"), Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 55000, DstPort: 53}
	_ = udp.SetNetworkLayerForChecksum(ip)
	dns := &layers.DNS{ID: 1, Questions: []layers.DNSQuestion{{Name: []byte("Example.COM"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	facts := PacketFacts(serializePacket(t, ethernet(), ip, udp, dns), testFact().Scope)
	if len(facts) != 3 || facts[1].Kind != "resolver" || facts[2].Kind != "dns" {
		t.Fatalf("facts = %+v", facts)
	}
	dns.QR = true
	if got := PacketFacts(serializePacket(t, ethernet(), ip, udp, dns), testFact().Scope); len(got) != 1 {
		t.Fatalf("reply became a resolver/query: %+v", got)
	}
}

func TestPacketFactsDHCPPrefix(t *testing.T) {
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("255.255.255.255"), Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 67, DstPort: 68}
	_ = udp.SetNetworkLayerForChecksum(ip)
	dhcp := &layers.DHCPv4{Operation: layers.DHCPOpReply, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6,
		YourClientIP: net.ParseIP("192.0.2.130"), ClientHWAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5}, Options: layers.DHCPOptions{
			{Type: layers.DHCPOptMessageType, Length: 1, Data: []byte{byte(layers.DHCPMsgTypeAck)}},
			{Type: layers.DHCPOptSubnetMask, Length: 4, Data: []byte{255, 255, 255, 128}},
		}}
	facts := PacketFacts(serializePacket(t, ethernet(), ip, udp, dhcp), testFact().Scope)
	if len(facts) != 4 || facts[1].Kind != "prefix" || facts[1].Value != "192.0.2.128/25" || facts[1].Provenance != "dhcp" {
		t.Fatalf("facts = %+v", facts)
	}
	dhcp.Options[1].Data = []byte{255, 0, 255, 0}
	for _, fact := range PacketFacts(serializePacket(t, ethernet(), ip, udp, dhcp), testFact().Scope) {
		if fact.Kind == "prefix" {
			t.Fatal("non-contiguous DHCP mask accepted")
		}
	}
}

func TestPacketFactsIPv6RouterPrefix(t *testing.T) {
	eth := ethernet()
	eth.EthernetType = layers.EthernetTypeIPv6
	ip := &layers.IPv6{Version: 6, HopLimit: 255, SrcIP: net.ParseIP("fe80::1"), DstIP: net.ParseIP("ff02::1"), NextHeader: layers.IPProtocolICMPv6}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterAdvertisement, 0)}
	_ = icmp.SetNetworkLayerForChecksum(ip)
	data := make([]byte, 30)
	data[0], data[1] = 64, 0x80
	binary.BigEndian.PutUint32(data[2:6], 3600)
	copy(data[14:], net.ParseIP("2001:db8:1::").To16())
	ra := &layers.ICMPv6RouterAdvertisement{Options: layers.ICMPv6Options{{Type: layers.ICMPv6OptPrefixInfo, Data: data}}}
	facts := PacketFacts(serializePacket(t, eth, ip, icmp, ra), testFact().Scope)
	if len(facts) != 2 || facts[1].Value != "2001:db8:1::/64" || facts[1].Provenance != "router-advertisement" {
		t.Fatalf("facts = %+v", facts)
	}
	ip.HopLimit = 64
	if got := PacketFacts(serializePacket(t, eth, ip, icmp, ra), testFact().Scope); len(got) != 1 {
		t.Fatal("routed RA accepted as on-link prefix")
	}
}
