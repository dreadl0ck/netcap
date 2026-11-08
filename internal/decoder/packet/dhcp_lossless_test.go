package packet

import (
	"bytes"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket/layers"
)

func TestDHCPBinaryOptionsOwnWireBytes(t *testing.T) {
	raw := []byte{0xff, 0x00, 0x80, 'a'}
	v4 := dhcpv4Decoder.Handler(&layers.DHCPv4{Options: layers.DHCPOptions{
		layers.NewDHCPOption(43, raw), layers.NewDHCPOption(12, raw), layers.NewDHCPOption(60, raw),
	}}, 1).(*types.DHCPv4)
	v6 := dhcpv6Decoder.Handler(&layers.DHCPv6{Options: layers.DHCPv6Options{
		layers.NewDHCPv6Option(17, raw),
	}}, 1).(*types.DHCPv6)
	want := append([]byte(nil), raw...)
	raw[0] = 0
	if !bytes.Equal(v4.Options[0].RawData, want) || !bytes.Equal(v6.Options[0].RawData, want) {
		t.Fatal("option retained borrowed packet storage")
	}
	if v4.Options[0].Data != "ff008061" || v6.Options[0].Data != "ff008061" || v4.Hostname != "ff008061" || v4.VendorClass != "ff008061" {
		t.Fatalf("binary presentation: v4=%+v v6=%+v", v4, v6)
	}
	for _, record := range []proto.Message{v4, v6} {
		if _, err := proto.Marshal(record); err != nil {
			t.Fatalf("binary DHCP broke protobuf output: %v", err)
		}
	}
}
