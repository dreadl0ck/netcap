package smb

import (
	"bytes"
	"encoding/binary"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"testing"
	"unicode/utf16"
)

func TestSMBFileCoverageRejectsHolesConflictsAndUnknownLength(t *testing.T) {
	for _, chunks := range [][]smbChunk{{{3, []byte("def")}, {0, []byte("abc")}}, {{0, []byte("abcd")}, {2, []byte("cdef")}}} {
		data, ok := completeSMBFile(&smbTransfer{size: 6, sizeKnown: true, chunks: chunks})
		if !ok || !bytes.Equal(data, []byte("abcdef")) {
			t.Fatal(data, ok)
		}
	}
	for _, transfer := range []*smbTransfer{
		{size: 6, sizeKnown: true, chunks: []smbChunk{{0, []byte("ab")}, {3, []byte("def")}}},
		{size: 6, sizeKnown: true, chunks: []smbChunk{{0, []byte("abcd")}, {2, []byte("XXef")}}},
		{size: 6, chunks: []smbChunk{{0, []byte("abcdef")}}},
	} {
		if _, ok := completeSMBFile(transfer); ok {
			t.Fatal("fabricated complete file", transfer)
		}
	}
}

func TestSMB2WriteReconstructionRequiresAcknowledgedCompleteRanges(t *testing.T) {
	text := func(s string) []byte {
		var b []byte
		for _, v := range utf16.Encode([]rune(s)) {
			b = binary.LittleEndian.AppendUint16(b, v)
		}
		return b
	}
	wire := func(command uint16, response bool, mid uint64, body []byte) []byte {
		h := make([]byte, 64)
		copy(h, []byte{254, 'S', 'M', 'B'})
		binary.LittleEndian.PutUint16(h[4:], 64)
		binary.LittleEndian.PutUint16(h[12:], command)
		if response {
			h[16] = 1
		}
		binary.LittleEndian.PutUint64(h[24:], mid)
		h[36], h[40] = 1, 1
		h = append(h, body...)
		return append([]byte{0, byte(len(h) >> 16), byte(len(h) >> 8), byte(len(h))}, h...)
	}
	fid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	tree := make([]byte, 8)
	share := text("\\\\srv\\WINDOWS")
	binary.LittleEndian.PutUint16(tree[4:], 72)
	binary.LittleEndian.PutUint16(tree[6:], uint16(len(share)))
	tree = append(tree, share...)
	create := make([]byte, 56)
	name := text("fixture.bin")
	binary.LittleEndian.PutUint16(create[44:], 120)
	binary.LittleEndian.PutUint16(create[46:], uint16(len(name)))
	create = append(create, name...)
	created := make([]byte, 88)
	created[4] = 2
	copy(created[64:], fid)
	write := make([]byte, 48)
	binary.LittleEndian.PutUint16(write[2:], 112)
	binary.LittleEndian.PutUint32(write[4:], 6)
	copy(write[16:], fid)
	write = append(write, []byte("abcdef")...)
	ack := make([]byte, 16)
	ack[4] = 6
	closeReq := make([]byte, 24)
	copy(closeReq[8:], fid)
	closed := make([]byte, 60)
	closed[2], closed[48] = 1, 6
	for _, badAck := range []bool{false, true} {
		response := append([]byte(nil), ack...)
		if badAck {
			response[4] = 7
		}
		messages := []struct {
			command  uint16
			response bool
			mid      uint64
			body     []byte
		}{{3, false, 1, tree}, {3, true, 1, make([]byte, 16)}, {5, false, 2, create}, {5, true, 2, created}, {9, false, 3, write}, {9, true, 3, response}, {6, false, 4, closeReq}, {6, true, 4, closed}}
		for split := 1; split < len(wire(9, false, 3, write)); split++ {
			var fragments core.DataFragments
			for _, m := range messages {
				data := wire(m.command, m.response, m.mid, m.body)
				dir := reassembly.TCPDirClientToServer
				if m.response {
					dir = reassembly.TCPDirServerToClient
				}
				if m.command == 9 && !m.response {
					fragments = append(fragments, &core.StreamData{RawData: data[:split], Dir: dir}, &core.StreamData{RawData: data[split:], Dir: dir})
				} else {
					fragments = append(fragments, &core.StreamData{RawData: data, Dir: dir})
				}
			}
			count := 0
			extractSMBFiles(&core.ConversationInfo{Data: fragments}, func(_ *smbTransfer, data []byte) {
				count++
				if string(data) != "abcdef" {
					t.Fatal("file bytes changed")
				}
			})
			if badAck && count != 0 || !badAck && count != 1 {
				t.Fatalf("badAck=%v split=%d files=%d", badAck, split, count)
			}
		}
	}
}
