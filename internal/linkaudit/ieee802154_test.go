package linkaudit

import (
	"encoding/binary"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"testing"
)

func TestIEEE802154MACAndUncompressedIPv6(t *testing.T) {
	if crc16([]byte("123456789")) != 0x2189 {
		t.Fatal("CRC-16/KERMIT check vector")
	}
	frame := []byte{0x41, 0x88, 7, 0x34, 0x12, 0x78, 0x56, 0xbc, 0x9a, 0x41}
	ip := make([]byte, 48)
	ip[0] = 0x60
	ip[5] = 8
	ip[6] = 17
	ip[7] = 64
	ip[8] = 0xfe
	ip[9] = 0x80
	ip[23] = 1
	ip[24] = 0xfe
	ip[25] = 0x80
	ip[39] = 2
	ip[41] = 1
	ip[43] = 2
	ip[45] = 8
	frame = append(frame, ip...)
	for _, fcs := range []bool{false, true} {
		data := append([]byte(nil), frame...)
		decode := gopacket.DecodeFunc(DecodeIEEE802154)
		if fcs {
			data = binary.LittleEndian.AppendUint16(data, crc16(data))
			decode = gopacket.DecodeFunc(DecodeIEEE802154FCS)
		}
		p := gopacket.NewPacket(data, decode, gopacket.Default)
		m, ok := p.LinkLayer().(*IEEE802154)
		if p.ErrorLayer() != nil || !ok || m.HeaderLength != 9 || m.PayloadProtocol != "6lowpan-ipv6" || m.HasFCS != fcs || fcs && !m.FCSValid {
			t.Fatalf("MAC evidence: %v", p)
		}
		n, ok := p.NetworkLayer().(*layers.IPv6)
		if !ok || n.SrcIP.String() != "fe80::1" || n.DstIP.String() != "fe80::2" {
			t.Fatal("IPv6 dispatch lost")
		}
	}
	p := gopacket.NewPacket([]byte{1, 0x21}, gopacket.DecodeFunc(DecodeIEEE802154), gopacket.Default)
	if p.ErrorLayer() != nil || !p.LinkLayer().(*IEEE802154).SequenceSuppressed {
		t.Fatal("2015 sequence suppression rejected")
	}
}
