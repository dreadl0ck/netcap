package packet

import (
	"encoding/binary"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestRADIUSAccountingPortReachability(t *testing.T) {
	for _, port := range []uint16{1813, 1646} {
		for _, response := range []bool{false, true} {
			raw := make([]byte, 8+29)
			sp, dp := uint16(40000), port
			if response {
				sp, dp = dp, sp
			}
			binary.BigEndian.PutUint16(raw, sp)
			binary.BigEndian.PutUint16(raw[2:], dp)
			binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)))
			raw[8] = 4
			if response {
				raw[8] = 5
			}
			raw[9] = 42
			binary.BigEndian.PutUint16(raw[10:], 29)
			copy(raw[28:], []byte{40, 6, 0, 0, 0, 1, 44, 3, 's'})
			p := gopacket.NewPacket(raw, layers.LayerTypeUDP, gopacket.Default)
			layer := p.Layer(layers.LayerTypeRADIUS)
			if layer == nil {
				t.Fatalf("port=%d response=%v: %v", port, response, p.ErrorLayer())
			}
			msg := radiusDecoder.Handler(layer, 123).(*types.RADIUS)
			if msg.Timestamp != 123 || msg.Identifier != 42 || msg.AcctStatusType != 1 || msg.AcctSessionID != "s" || msg.IsRequest == response || msg.AuthSuccess {
				t.Fatalf("accounting semantics: %+v", msg)
			}
		}
	}
}
