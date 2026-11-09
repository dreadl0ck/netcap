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
