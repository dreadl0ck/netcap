package packet

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestNBNSRegistrationPreservesNameSuffixAndGroup(t *testing.T) {
	for _, group := range []bool{false, true} {
		data := make([]byte, 12)
		binary.BigEndian.PutUint16(data, 42)
		binary.BigEndian.PutUint16(data[2:], 5<<11)
		binary.BigEndian.PutUint16(data[4:], 1)
		binary.BigEndian.PutUint16(data[10:], 1)
		name := []byte("DESKTOP-TEST   ")
		name = append(name, 0x20)
		data = append(data, 32)
		for _, b := range name {
			data = append(data, 'A'+b>>4, 'A'+b&15)
		}
		data = append(data, 0, 0, 0x20, 0, 1, 0xc0, 0x0c, 0, 0x20, 0, 1, 0, 0, 0, 0, 0, 6)
		flags := byte(0x40)
		if group {
			flags |= 0x80
		}
		data = append(data, flags, 0, 192, 0, 2, 1)
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.255")}
		u := &layers.UDP{SrcPort: 137, DstPort: 137}
		_ = u.SetNetworkLayerForChecksum(ip)
		b := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, u, gopacket.Payload(data)); err != nil {
			t.Fatal(err)
		}
		p := gopacket.NewPacket(b.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
		m := decodeNBNS(p)
		if m == nil {
			t.Fatal("registration rejected")
		}
		r := m.(*types.NBNS)
		if r.ID != 42 || r.OpCode != 5 || len(r.Names) != 2 || r.Names[1].Name != "DESKTOP-TEST" || r.Names[1].Suffix != 0x20 || r.Names[1].IP != "192.0.2.1" || r.Names[1].Group != group {
			t.Fatalf("registration fields: %+v", r)
		}
	}
}

func nbnsDatagram(t *testing.T, data []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.9"), DstIP: net.ParseIP("192.0.2.1")}
	u := &layers.UDP{SrcPort: 137, DstPort: 137}
	_ = u.SetNetworkLayerForChecksum(ip)
	b := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, u, gopacket.Payload(data)); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(b.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

func encodeNBName(name string, suffix byte) []byte {
	raw := []byte(name + "               ")[:15]
	raw = append(raw, suffix)
	out := []byte{32}
	for _, b := range raw {
		out = append(out, 'A'+b>>4, 'A'+b&15)
	}
	return append(out, 0)
}

// Node-status (type 0x21) responses used to be dropped because layers.DNS decodes type 33 as SRV.
func TestNBNSNodeStatusResponseIsDecoded(t *testing.T) {
	data := make([]byte, 12)
	binary.BigEndian.PutUint16(data, 7)
	binary.BigEndian.PutUint16(data[2:], 0x8400)
	binary.BigEndian.PutUint16(data[6:], 1)
	data = append(data, encodeNBName("*", 0)...)
	data = append(data, 0, 0x21, 0, 1, 0, 0, 0, 0)
	rdata := []byte{2}
	for _, e := range []struct {
		name   string
		suffix byte
		flags  uint16
	}{{"WORKSTATION1", 0x00, 0x0400}, {"WORKGROUP", 0x00, 0x8400}} {
		entry := []byte((e.name + "               ")[:15])
		entry = append(entry, e.suffix, byte(e.flags>>8), byte(e.flags))
		rdata = append(rdata, entry...)
	}
	rdata = append(rdata, make([]byte, 46)...) // statistics block
	data = binary.BigEndian.AppendUint16(data, uint16(len(rdata)))
	data = append(data, rdata...)

	m := decodeNBNS(nbnsDatagram(t, data))
	if m == nil {
		t.Fatal("node status response rejected")
	}
	r := m.(*types.NBNS)
	if !r.Response || r.ID != 7 || len(r.Names) != 2 || r.Names[0].Name != "WORKSTATION1" || r.Names[0].Group || r.Names[1].Name != "WORKGROUP" || !r.Names[1].Group || r.Names[1].Type != 0x21 {
		t.Fatalf("node status fields: %+v", r)
	}
}

func TestNBNSRejectsTruncatedAndLoopingMessages(t *testing.T) {
	data := make([]byte, 12)
	binary.BigEndian.PutUint16(data[4:], 1)
	data = append(data, 0xc0, 12, 0, 0x20, 0, 1) // compression pointer to itself
	if decodeNBNS(nbnsDatagram(t, data)) != nil {
		t.Fatal("pointer loop accepted")
	}
	data = append(make([]byte, 12), 32, 'A')
	binary.BigEndian.PutUint16(data[4:], 1)
	if decodeNBNS(nbnsDatagram(t, data)) != nil {
		t.Fatal("truncated label accepted")
	}
}
