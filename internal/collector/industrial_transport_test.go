package collector

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket/layers"
)

// ADS ReadState has an AMS header and no service body. Each connection below
// carries two requests; splitting or repeating TCP segments must not change that.
func readStatePDU(id uint32) []byte {
	b := make([]byte, 38)
	binary.LittleEndian.PutUint32(b[2:], 32)
	copy(b[6:12], []byte{192, 0, 2, 2, 1, 1})
	binary.LittleEndian.PutUint16(b[12:], 851)
	copy(b[14:20], []byte{192, 0, 2, 1, 1, 1})
	binary.LittleEndian.PutUint16(b[20:], 32000)
	binary.LittleEndian.PutUint16(b[22:], 4)
	binary.LittleEndian.PutUint16(b[24:], 4)
	binary.LittleEndian.PutUint32(b[34:], id)
	return b
}

func TestIndustrialAMSTCPDelivery(t *testing.T) {
	b, input := newBookCapture(t)
	first, second := readStatePDU(17), readStatePDU(18)
	const src, dst = "192.0.2.1", "192.0.2.2"
	for cut := 1; cut < len(first); cut++ {
		port := uint16(40000 + cut)
		b.openTCP(src, dst, port, 48898, false)
		send := func(seq uint32, data []byte) {
			b.packet(src, dst, &layers.TCP{SrcPort: layers.TCPPort(port), DstPort: 48898, Seq: seq, Ack: 5001, ACK: true, PSH: true, Window: 65535}, string(data), false)
		}
		tail := append(bytes.Clone(first[cut:]), second...)
		if cut%2 == 0 {
			send(1001+uint32(cut), tail)
		}
		send(1001, first[:cut])
		send(1001, first[:cut])
		send(1001+uint32(cut), tail)
	}
	// A known flow ending during its second message retains a loss record.
	b.conversation(src, dst, 41000, 48898, false, bookMessage{text: string(first)}, bookMessage{text: string(second[:5])})
	for _, workers := range []int{1, 3} {
		out := runVoIP(t, input, "AMS", workers)
		rows := bookRecords(t, out, "AMS", func() *types.AMS { return new(types.AMS) })
		byPort := map[int32][]uint32{}
		partial := 0
		for _, r := range rows {
			if r.Assembly.GetStatus() == "incomplete" {
				if r.Context.SrcPort != 41000 || r.ADSCommand != "" {
					t.Fatalf("invalid partial: %v", r)
				}
				partial++
				continue
			}
			if r.Context.SrcIP != src || r.Context.GetCommunityID() == "" || r.ADSCommand == "" || r.Length != 32 || r.Assembly.GetStatus() != "complete" {
				t.Fatalf("invalid complete: %v", r)
			}
			byPort[r.Context.SrcPort] = append(byPort[r.Context.SrcPort], r.InvokeID)
		}
		if partial != 1 || !slices.Equal(byPort[41000], []uint32{17}) {
			t.Fatalf("EOF: %d partial, ids %v", partial, byPort[41000])
		}
		for cut := 1; cut < len(first); cut++ {
			if ids := byPort[int32(40000+cut)]; !slices.Equal(ids, []uint32{17, 18}) {
				t.Fatalf("workers %d, split %d: %v", workers, cut, ids)
			}
		}
	}
}

func TestIndustrialPacketOnlyUADP(t *testing.T) {
	b, input := newBookCapture(t)
	// UADP v1, one DataSetWriterId, a key frame with one Int32 variant.
	b.udp("192.0.2.1", "192.0.2.2", 42000, 4840, []byte{0x41, 1, 0x34, 0x12, 1, 1, 0, 6, 7, 0, 0, 0})
	t.Setenv("W76_PACKET_ONLY", "1")
	out := runVoIP(t, input, "OPCUAPubSub,OPCUA", 2)
	rows := bookRecords(t, out, "OPCUAPubSub", func() *types.OPCUAPubSub { return new(types.OPCUAPubSub) })
	if len(rows) != 1 || rows[0].Version != 1 || !slices.Equal(rows[0].DataSetWriterIDs, []uint32{0x1234}) || rows[0].Encrypted || rows[0].Chunk || rows[0].PayloadError != "" {
		t.Fatalf("UADP: %v", rows)
	}
}
