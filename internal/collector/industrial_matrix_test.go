package collector

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

func industrialHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// These are complete benign requests or link-test messages; the TCP deliveries
// vary independently of their application framing. No network interface is used.
func TestIndustrialTCPMatrix(t *testing.T) {
	const src, dst = "192.0.2.1", "192.0.2.2"
	hello := append([]byte("HELF\x20\x00\x00\x00"), make([]byte, 24)...)
	mms := industrialHex(t, "0300001c02f08001000100610f300d020103a008a0060202114f8200")
	s7 := industrialHex(t, "0300001302f080320100000001000200000400")
	cases := []struct {
		name  string
		port  uint16
		wire  []byte
		new   func() proto.Message
		check func(proto.Message) (int32, bool)
	}{
		{"Modbus", 502, industrialHex(t, "0001000000060103000a0001"), func() proto.Message { return new(types.Modbus) }, func(m proto.Message) (int32, bool) {
			r := m.(*types.Modbus)
			return r.SrcPort, r.ParseStatus == "valid" && r.FunctionCode == 3 && r.HasAddress && r.Address == 10
		}},
		{"DNP3", 20000, industrialHex(t, "05640bc403000400ef7ac1c1013c0206b576"), func() proto.Message { return new(types.DNP3) }, func(m proto.Message) (int32, bool) {
			r := m.(*types.DNP3)
			return r.SrcPort, r.ParseStatus == "valid" && r.FunctionCode == 1 && r.HeaderCRCValid && r.BlockCRCValid
		}},
		{"OPCUA", 4840, hello, func() proto.Message { return new(types.OPCUA) }, func(m proto.Message) (int32, bool) {
			r := m.(*types.OPCUA)
			return r.SrcPort, r.Assembly.GetStatus() == "complete" && r.MessageType == "HEL" && r.MessageSize == 32
		}},
		{"IEC104", 2404, []byte{0x68, 4, 0x43, 0, 0, 0}, func() proto.Message { return new(types.IEC104) }, func(m proto.Message) (int32, bool) {
			r := m.(*types.IEC104)
			return r.Context.GetSrcPort(), r.Assembly.GetStatus() == "complete" && r.UFunction != ""
		}},
		{"S7Comm", 102, s7, func() proto.Message { return new(types.S7Comm) }, func(m proto.Message) (int32, bool) {
			r := m.(*types.S7Comm)
			return r.SrcPort, r.Assembly.GetStatus() == "complete" && r.ProtocolId == 0x32 && r.FunctionCode == 4
		}},
		{"MMS", 102, mms, func() proto.Message { return new(types.MMS) }, func(m proto.Message) (int32, bool) {
			r := m.(*types.MMS)
			return r.Context.GetSrcPort(), r.Assembly.GetStatus() == "complete" && r.InvokeID == 4431
		}},
		{"MMS", 32102, mms, func() proto.Message { return new(types.MMS) }, func(m proto.Message) (int32, bool) {
			r := m.(*types.MMS)
			return r.Context.GetSrcPort(), r.Assembly.GetStatus() == "complete" && r.InvokeID == 4431
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, path := newBookCapture(t)
			for cut := 1; cut < len(tc.wire); cut++ {
				port := uint16(43500 + cut)
				b.openTCP(src, dst, port, tc.port, false)
				send := func(seq uint32, data []byte) {
					b.packet(src, dst, &layers.TCP{SrcPort: layers.TCPPort(port), DstPort: layers.TCPPort(tc.port), Seq: seq, Ack: 5001, ACK: true, PSH: true, Window: 65535}, string(data), false)
				}
				tail := append(bytes.Clone(tc.wire[cut:]), tc.wire...)
				if cut%2 == 0 {
					send(1001+uint32(cut), tail)
				}
				send(1001, tc.wire[:cut])
				send(1001, tc.wire[:cut])
				send(1001+uint32(cut), tail)
			}
			// Preserve the start and end of a PDU but omit its middle. The preceding
			// intact PDU establishes attribution even for a capture ending in loss.
			const gapPort = 44000
			b.openTCP(src, dst, gapPort, tc.port, false)
			sendGap := func(seq uint32, data []byte) {
				b.packet(src, dst, &layers.TCP{SrcPort: gapPort, DstPort: layers.TCPPort(tc.port), Seq: seq, Ack: 5001, ACK: true, PSH: true, Window: 65535}, string(data), false)
			}
			cut := len(tc.wire) / 2
			sendGap(1001, append(bytes.Clone(tc.wire), tc.wire[:cut]...))
			sendGap(1001+uint32(len(tc.wire)+cut+1), tc.wire[cut+1:])
			for _, workers := range []int{1, 3} {
				out := runVoIP(t, path, tc.name, workers)
				counts := map[int32]int{}
				for _, r := range bookRecords(t, out, tc.name, tc.new) {
					port, ok := tc.check(r)
					if ok {
						counts[port]++
					} else if port != gapPort {
						t.Fatalf("workers %d unexpected %s record: %v", workers, tc.name, r)
					}
				}
				for cut := 1; cut < len(tc.wire); cut++ {
					if n := counts[int32(43500+cut)]; n != 2 {
						t.Fatalf("workers %d split %d: %d complete PDUs", workers, cut, n)
					}
				}
				if counts[gapPort] != 1 {
					t.Fatalf("gap yielded %d complete PDUs", counts[gapPort])
				}
			}
		})
	}
}

func TestIndustrialIEC104SharedPort(t *testing.T) {
	b, path := newBookCapture(t)
	security := industrialHex(t, "680c000000005401060001002a00")
	plain := []byte{0x68, 4, 0x43, 0, 0, 0}
	b.conversation("192.0.2.1", "192.0.2.2", 41001, 2404, false, bookMessage{text: string(plain)}, bookMessage{text: string(security[:4])}, bookMessage{server: true, text: string(plain)}, bookMessage{text: string(security[4:])}, bookMessage{text: string(plain)})
	out := runVoIP(t, path, "IEC104,IEC62351", 2)
	apdus := bookRecords(t, out, "IEC104", func() *types.IEC104 { return new(types.IEC104) })
	sec := bookRecords(t, out, "IEC62351", func() *types.IEC62351 { return new(types.IEC62351) })
	if len(apdus) != 4 || len(sec) != 1 || sec[0].MessageType != 84 || sec[0].UserIdentity != "42" || !sec[0].IsKeyManagementEvent || sec[0].MACValid {
		t.Fatalf("APDUs=%d security=%v", len(apdus), sec)
	}
}
