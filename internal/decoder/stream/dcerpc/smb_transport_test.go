package dcerpc

import (
	"bytes"
	"encoding/binary"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"testing"
	"unicode/utf16"
)

func smbFrame(command uint16, response bool, mid uint64, body []byte) []byte {
	b := make([]byte, 64)
	copy(b, []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(b[4:], 64)
	binary.LittleEndian.PutUint16(b[12:], command)
	if response {
		b[16] = 1
	}
	binary.LittleEndian.PutUint64(b[24:], mid)
	b[36] = 1
	b[40] = 1
	b = append(b, body...)
	return append([]byte{0, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b...)
}

func TestSMB2PipeTransportRetainsClosedPipe(t *testing.T) {
	name := utf16.Encode([]rune("samr"))
	create := make([]byte, 56)
	binary.LittleEndian.PutUint16(create[44:], 120)
	binary.LittleEndian.PutUint16(create[46:], uint16(len(name)*2))
	for _, u := range name {
		create = binary.LittleEndian.AppendUint16(create, u)
	}
	created := make([]byte, 88)
	created[64] = 42
	write := make([]byte, 48)
	write[16] = 42
	binary.LittleEndian.PutUint16(write[2:], 112)
	binary.LittleEndian.PutUint32(write[4:], 3)
	write = append(write, 1, 2, 3)
	read := make([]byte, 48)
	read[16] = 42
	readResult := make([]byte, 16)
	readResult[2] = 80
	binary.LittleEndian.PutUint32(readResult[4:], 3)
	readResult = append(readResult, 4, 5, 6)
	close := make([]byte, 24)
	close[8] = 42
	fragments := core.DataFragments{}
	for _, m := range []struct {
		command  uint16
		response bool
		mid      uint64
		body     []byte
	}{
		{5, false, 1, create}, {5, true, 1, created}, {9, false, 2, write}, {8, false, 3, read}, {8, true, 3, readResult}, {6, false, 4, close},
	} {
		dir := reassembly.TCPDirClientToServer
		if m.response {
			dir = reassembly.TCPDirServerToClient
		}
		fragments = append(fragments, &core.StreamData{Dir: dir, RawData: smbFrame(m.command, m.response, m.mid, m.body)})
	}
	pipes := smbPipeConversations(&core.ConversationInfo{Ident: "flow", Data: fragments})
	if len(pipes) != 1 || len(pipes[0].Data) != 2 || !bytes.Equal(pipes[0].Data[0].Raw(), []byte{1, 2, 3}) || !bytes.Equal(pipes[0].Data[1].Raw(), []byte{4, 5, 6}) || pipes[0].Data[1].Direction() != reassembly.TCPDirServerToClient {
		t.Fatalf("pipe evidence: %#v", pipes)
	}
	withGap := append(append(core.DataFragments{}, fragments...), &core.StreamData{SkippedBytes: 1, RawData: []byte("lost")})
	if p := smbPipeConversations(&core.ConversationInfo{Data: withGap}); len(p) != 1 || len(p[0].Data) != 2 {
		t.Fatal("later loss erased earlier pipe evidence", p)
	}
	fragments[0].(*core.StreamData).SkippedBytes = -1
	if p := smbPipeConversations(&core.ConversationInfo{Data: fragments}); len(p) != 1 || len(p[0].Data) != 2 {
		t.Fatal("initial unknown gap rejected complete SMB framing", p)
	}
	fragments[2].(*core.StreamData).SkippedBytes = 1
	if p := smbPipeConversations(&core.ConversationInfo{Data: fragments}); p != nil {
		t.Fatal("pipe evidence stitched across loss")
	}
}

func TestSAMRRequestResponseCorrelationAndFragmentation(t *testing.T) {
	d := &dcerpcReader{contexts: map[uint16]string{0: "12345778-1234-abcd-ef00-0123456789ac"}, ndr32: map[uint16]bool{0: true}, calls: map[uint32][]call{}}
	pdu := func(typ, flags byte, body []byte) []byte {
		b := make([]byte, 24)
		b[0] = 5
		b[2] = typ
		b[3] = flags
		b[4] = 0x10
		binary.LittleEndian.PutUint16(b[8:], uint16(len(b)+len(body)))
		binary.LittleEndian.PutUint32(b[12:], 1)
		if typ == 0 {
			binary.LittleEndian.PutUint16(b[22:], 36)
		}
		return append(b, body...)
	}
	request := make([]byte, 22)
	binary.LittleEndian.PutUint16(request[20:], 21)
	d.parsePDU(pdu(0, 3, request), binary.LittleEndian)
	reply := samrNameReply(21, "bdiaz", "Test Analyst")
	first := d.parsePDU(pdu(2, 1, reply[:100]), binary.LittleEndian)
	last := d.parsePDU(pdu(2, 2, reply[100:]), binary.LittleEndian)
	if first.IdentityStatus != "pending_fragments" || last.IdentityStatus != "decoded_ndr32" || len(last.Identities) != 1 || last.Identities[0].FullName != "Test Analyst" || d.pending != 0 {
		t.Fatal(first, last)
	}
	if len(d.stubFragments) != 0 {
		t.Fatal("completed stubs retained")
	}
}

func TestLSALookupSIDInputs(t *testing.T) {
	b := make([]byte, 36)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint32(b[24:], 0x20000)
	binary.LittleEndian.PutUint32(b[28:], 1)
	binary.LittleEndian.PutUint32(b[32:], 0x20004)
	b = binary.LittleEndian.AppendUint32(b, 2)
	b = append(b, 1, 2, 0, 0, 0, 0, 0, 5)
	b = binary.LittleEndian.AppendUint32(b, 21)
	b = binary.LittleEndian.AppendUint32(b, 1001)
	names, status := lsaLookupInputs(b, 15, binary.LittleEndian)
	if status != "decoded_ndr32_request" || len(names) != 1 || names[0].SID != "S-1-5-21-1001" {
		t.Fatal(names, status)
	}
	b[40] = 2
	if names, _ := lsaLookupInputs(b, 15, binary.LittleEndian); names != nil {
		t.Fatal("invalid SID revision accepted")
	}
}
