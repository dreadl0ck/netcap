package packet

import (
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"testing"
)

func TestDHCPRequestListNotOuterOptions(t *testing.T) {
	d := &layers.DHCPv4{Operation: layers.DHCPOpRequest, HardwareType: layers.LinkTypeEthernet,
		Options: layers.DHCPOptions{layers.NewDHCPOption(53, []byte{1}), layers.NewDHCPOption(55, []byte{1, 3, 6})}}
	b := gopacket.NewSerializeBuffer()
	if err := d.SerializeTo(b, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		t.Fatal(err)
	}
	p := gopacket.NewPacket(b.Bytes(), layers.LayerTypeDHCPv4, gopacket.Default)
	if got := extractDHCPFingerprint(p); got != "1,3,6" {
		t.Fatalf("PRL: %q", got)
	}
	raw := dhcpv4Decoder.Handler(d, 1).(*types.DHCPv4)
	if raw.Fingerprint != "53,55" {
		t.Fatalf("outer options changed: %q", raw.Fingerprint)
	}
	// DHCPv6 outer option codes never become a v4 catalogue key.
	p = gopacket.NewPacket([]byte{1, 0, 0, 1, 0, 1, 0, 0}, layers.LayerTypeDHCPv6, gopacket.Default)
	if got := extractDHCPFingerprint(p); got != "" {
		t.Fatal(got)
	}
}
