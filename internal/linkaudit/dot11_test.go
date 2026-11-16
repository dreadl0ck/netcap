package linkaudit

import (
	"bytes"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestProtectedManagementBodyIsOpaque(t *testing.T) {
	frame := make([]byte, 24)
	frame[0], frame[1] = 0xb0, 0x40
	body := []byte{1, 2, 3, 0, 0xff, 0xff, 0xff, 0xff}
	frame = append(frame, body...)
	p := gopacket.NewPacket(frame, gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error { return DecodeDot11(data, p, false) }), gopacket.Default)
	if p.ErrorLayer() != nil || p.Layer(layers.LayerTypeDot11) == nil || !bytes.Equal(p.ApplicationLayer().Payload(), body) {
		t.Fatalf("protected body parsed or lost: %v", p)
	}
	if p.Layer(layers.LayerTypeDot11InformationElement) != nil {
		t.Fatal("encrypted bytes interpreted as information elements")
	}
}
