package opcua

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

func uaFrame(typ string, chunk byte, seq, id uint32, data []byte) []byte {
	put := binary.LittleEndian.AppendUint32
	b := put(append([]byte(typ), chunk, 0, 0, 0, 0), 9)
	if typ == "OPN" {
		policy := layers.OPCUASecurityPolicyNone
		b = append(put(b, uint32(len(policy))), policy...)
		b = put(put(b, 0xffffffff), 0xffffffff)
	} else {
		b = put(b, 1)
	}
	b = append(put(put(b, seq), id), data...)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	return b
}

func TestChunkLifecycle(t *testing.T) {
	// ReadRequest type, null authentication token and empty request header,
	// max age, timestamps-to-return and an empty nodes-to-read array.
	body := append([]byte{1, 0, 0x77, 2}, make([]byte, 29+16)...)
	body[14] = 42 // request handle
	open := uaFrame("OPN", 'F', 1, 0, nil)
	part := func(seq, id uint32) []byte { return uaFrame("MSG", 'C', seq, id, body[:17]) }
	end := func(seq, id uint32) []byte { return uaFrame("MSG", 'F', seq, id, body[17:]) }
	abort := uaFrame("MSG", 'A', 5, 8, []byte{0, 0, 0xb8, 0x80, 4, 0, 0, 0, 's', 't', 'o', 'p'})
	for _, tc := range []struct {
		name   string
		limit  int64
		frames [][]byte
		gap    int
		check  func(*testing.T, []*types.OPCUA)
	}{
		{"interleaved-abort", 64, [][]byte{open, part(2, 7), part(3, 8), end(4, 7), abort}, -1, func(t *testing.T, rows []*types.OPCUA) {
			if len(rows) != 5 || rows[3].ServiceName != "ReadRequest" || rows[3].RequestHandle != 42 || rows[3].RequestId != 7 || rows[3].Timestamp != 2 || rows[3].Assembly.Pieces != 2 || rows[4].RequestId != 8 || rows[4].SequenceNumber != 5 || rows[4].Timestamp != 3 || rows[4].ErrorReason != "stop" || rows[4].Assembly.Status != "aborted" {
				t.Fatalf("joined/aborted rows: %v", rows)
			}
		}},
		{"lost-sequence", 64, [][]byte{open, part(2, 7), end(4, 7), uaFrame("MSG", 'F', 5, 9, body)}, -1, func(t *testing.T, rows []*types.OPCUA) {
			if len(rows) != 4 || rows[2].RequestId != 7 || rows[2].Assembly.Status != "incomplete" || rows[2].Assembly.Pieces != 2 || rows[2].Timestamp != 2 || rows[2].ServiceName != "" || rows[3].ServiceName != "ReadRequest" {
				t.Fatalf("loss and recovery: %v", rows)
			}
		}},
		{"gap", 64, [][]byte{open, part(2, 7), end(3, 7)}, 2, func(t *testing.T, rows []*types.OPCUA) {
			if len(rows) != 4 || rows[2].Assembly.Reason != "capture gap" || rows[2].Timestamp != 2 || rows[3].Assembly.Status != "opaque" || rows[3].RequestId != 0 {
				t.Fatalf("gap: %v", rows)
			}
		}},
		{"eof", 64, [][]byte{open, part(2, 7)}, -1, func(t *testing.T, rows []*types.OPCUA) {
			if len(rows) != 3 || rows[2].Assembly.Reason != "EOF" || rows[2].Timestamp != 2 || rows[2].RequestId != 7 {
				t.Fatalf("EOF: %v", rows)
			}
		}},
		{"budget", 8, [][]byte{open, part(2, 7), end(3, 7)}, -1, func(t *testing.T, rows []*types.OPCUA) {
			if len(rows) != 3 || rows[1].Assembly.Reason != "chunk budget" || rows[2].Assembly.Status != "opaque" {
				t.Fatalf("byte cap: %v", rows)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := core.NewStateBudget(tc.limit, nil)
			if err != nil {
				t.Fatal(err)
			}
			c := &core.ConversationInfo{StateBudget: b, ClientIP: "192.0.2.1", ServerIP: "192.0.2.2"}
			for i, wire := range tc.frames {
				f := &core.StreamData{RawData: wire, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, int64(i+1))}}
				if i == tc.gap {
					f.SkippedBytes = 1
				}
				c.Data = append(c.Data, f)
			}
			var rows []*types.OPCUA
			(&opcuaReader{c}).walk(func(r *types.OPCUA) { rows = append(rows, r) })
			if h := b.Health(); h.RetainedBytes != 0 || h.PeakBytes > tc.limit || c.FragmentError != nil {
				t.Fatalf("budget: %+v, %v", h, c.FragmentError)
			}
			tc.check(t, rows)
		})
	}
}
