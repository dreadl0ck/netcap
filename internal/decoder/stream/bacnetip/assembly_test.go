package bacnetip

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

func segmentPacket(seq byte, more bool, data []byte) gopacket.Packet {
	flags := byte(8)
	if more {
		flags |= 4
	}
	// Original-Unicast-NPDU: confirmed ReadPropertyMultiple, invoke ID 1.
	b := append([]byte{0x81, 0x0a, 0, 0, 1, 4, flags, 5, 1, seq, 7, 14}, data...)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return gopacket.NewPacket(b, layers.LayerTypeBVLC, gopacket.Default)
}

func TestSegmentLifecycle(t *testing.T) {
	var a Assembly
	var ended []*types.BACnetIP
	emit := func(r *types.BACnetIP) { ended = append(ended, r) }
	at := int64(0)
	feed := func(peer string, seq byte, more bool, data []byte) *types.BACnetIP {
		at++
		return a.Decode(segmentPacket(seq, more, data), peer, "BACnet/IP", &types.PacketContext{DstIP: peer}, at, false, emit)
	}
	value := bytes.Repeat([]byte{0x0c, 0, 0, 0, 1, 0x1e, 9, 85, 0x1f}, 30)
	peer := "192.0.2.2"
	feed(peer, 0, true, value[:1])
	feed("192.0.2.3", 0, true, value[:1])
	feed(peer, 2, true, value[2:3])
	for _, seq := range []int{0, 2} {
		r := feed(peer, byte(seq), true, value[seq:seq+1])
		if r.Assembly.Status != "duplicate" || r.Assembly.Pieces != 2 {
			t.Fatal(r)
		}
	}
	for i := 1; i < len(value); i++ {
		if i == 2 {
			continue
		}
		r := feed(peer, byte(i), i+1 < len(value), value[i:i+1])
		if i+1 == len(value) && (r.Assembly.Status != "complete" || r.Assembly.Pieces != uint32(len(value)) || r.Timestamp != 1 || r.ServiceChoice != 14 || r.DstIP != peer) {
			t.Fatal(r)
		}
	}
	a.Flush(at, false, emit)
	if len(ended) != 1 || ended[0].Timestamp != 2 || ended[0].DstIP != "192.0.2.3" || ended[0].Assembly.Reason != "idle expiry" {
		t.Fatalf("peer expiry: %v", ended)
	}
	for i := 0; i < 64; i++ {
		feed(fmt.Sprint(i), 0, true, value[:1])
	}
	if r := feed("over cap", 0, true, value[:1]); r.Assembly.Status != "limited" {
		t.Fatal(r)
	}
	first := at + 1
	feed("0", 0, true, value[:2]) // a distinctly different initial segment reuses the invoke ID
	if len(ended) != 2 || ended[1].Assembly.Reason != "invoke ID reused" {
		t.Fatal(ended)
	}
	a.Flush(0, true, emit)
	if len(ended) != 66 || len(a.pending) != 0 {
		t.Fatalf("EOF: %d ended, %d pending", len(ended), len(a.pending))
	}
	for _, r := range ended[2:] {
		if r.Assembly.Reason != "EOF" || r.Assembly.Pieces != 1 || r.DstIP == "0" && r.Timestamp != first {
			t.Fatal(r)
		}
	}
}
