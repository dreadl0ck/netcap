package dcerpc

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

func smbWide(name string) (b []byte) {
	for _, u := range utf16.Encode([]rune(name)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return
}

func smb2Fragment(cmd uint16, reply bool, mid uint64, body []byte) *core.StreamData {
	return fragment(smbFrame(cmd, reply, mid, body), int64(mid)*100+int64(len(body)), reply)
}

func smb2CreatePair(mid uint64, name string, fid byte) core.DataFragments {
	b := make([]byte, 56)
	n := smbWide(name)
	binary.LittleEndian.PutUint16(b[44:], 120)
	binary.LittleEndian.PutUint16(b[46:], uint16(len(n)))
	r := make([]byte, 88)
	r[64] = fid
	return core.DataFragments{smb2Fragment(5, false, mid, append(b, n...)), smb2Fragment(5, true, mid, r)}
}

func smb2Open(name string, fid byte) core.DataFragments {
	r := make([]byte, 16)
	r[2] = 2
	return append(core.DataFragments{smb2Fragment(3, false, 0, make([]byte, 8)), smb2Fragment(3, true, 0, r)}, smb2CreatePair(1, name, fid)...)
}

func smb2WritePair(mid uint64, fid byte, data []byte) core.DataFragments {
	b := make([]byte, 48)
	b[16] = fid
	binary.LittleEndian.PutUint16(b[2:], 112)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(data)))
	r := make([]byte, 16)
	binary.LittleEndian.PutUint32(r[4:], uint32(len(data)))
	return core.DataFragments{smb2Fragment(9, false, mid, append(b, data...)), smb2Fragment(9, true, mid, r)}
}

func smb2ReadPair(mid uint64, fid byte, data []byte) core.DataFragments {
	b := make([]byte, 48)
	b[16] = fid
	binary.LittleEndian.PutUint32(b[4:], uint32(len(data)))
	r := make([]byte, 16)
	r[2] = 80
	binary.LittleEndian.PutUint32(r[4:], uint32(len(data)))
	return core.DataFragments{smb2Fragment(8, false, mid, b), smb2Fragment(8, true, mid, append(r, data...))}
}

func smb2IOCTLPair(mid uint64, fid byte, in, out []byte) core.DataFragments {
	b := make([]byte, 56)
	b[8] = fid
	binary.LittleEndian.PutUint32(b[4:], 0x11c017)
	binary.LittleEndian.PutUint32(b[24:], 120)
	binary.LittleEndian.PutUint32(b[28:], uint32(len(in)))
	binary.LittleEndian.PutUint32(b[44:], uint32(len(out)))
	binary.LittleEndian.PutUint32(b[48:], 1)
	r := make([]byte, 48)
	r[8] = fid
	binary.LittleEndian.PutUint32(r[4:], 0x11c017)
	binary.LittleEndian.PutUint32(r[32:], 112)
	binary.LittleEndian.PutUint32(r[36:], uint32(len(out)))
	return core.DataFragments{smb2Fragment(11, false, mid, append(b, in...)), smb2Fragment(11, true, mid, append(r, out...))}
}

func pipeRecords(data core.DataFragments) ([]*core.ConversationInfo, []*types.DCERPC) {
	pipes := smbPipeConversations(&core.ConversationInfo{Ident: "fixture", CommunityID: "cid", ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 50000, ServerPort: 445, Data: data})
	var records []*types.DCERPC
	for _, p := range pipes {
		records = append(records, decodeAll(p)...)
	}
	return pipes, records
}

func TestSMB2GeneralPipeInterfaces(t *testing.T) {
	for _, tc := range []struct {
		name, uuid, iface string
		op                uint16
	}{
		{"samr", uuidSAMR, "SAMR", 64},
		{"\\PIPE\\lsarpc", "12345778-1234-abcd-ef00-0123456789ab", "LSARPC", 44},
		{"srvsvc", "4b324fc8-1670-01d3-1278-5a47bf6ee188", "SRVSVC", 15},
		{"spoolss", "12345678-1234-abcd-ef00-0123456789ab", "SPOOLSS", 1},
		{"svcctl", uuidSVCCTL, "SVCCTL", 12},
		{"custom-管道", "e3514235-4b06-11d1-ab04-00c04fc2dcd2", "DRSUAPI", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := smb2Open(tc.name, 42)
			binding := bind(1, tc.uuid)
			// SMB writes split an RPC header; SMB reads split a response body.
			data = append(data, smb2WritePair(2, 42, binding[:7])...)
			data = append(data, smb2WritePair(3, 42, binding[7:])...)
			data = append(data, smb2IOCTLPair(4, 42, request(2, 0, tc.op), response(ptypeResponse, 2, 0, 0))...)
			data = append(data, smb2WritePair(5, 42, request(3, 0, tc.op))...)
			reply := response(ptypeResponse, 3, 0, 0)
			data = append(data, smb2ReadPair(6, 42, reply[:19])...)
			data = append(data, smb2ReadPair(7, 42, reply[19:])...)
			pipes, records := pipeRecords(data)
			if len(pipes) != 1 || len(records) != 5 {
				t.Fatalf("pipes=%d records=%v", len(pipes), records)
			}
			for i, r := range records {
				if r.InterfaceName != tc.iface || r.CommunityID != "cid" || (i != 0 && r.OpNum != int32(tc.op)) {
					t.Fatalf("record %d: %+v", i, r)
				}
			}
			if records[2].SrcIP != "192.0.2.2" || records[4].Timestamp != core.FragmentTime(data[len(data)-3]) {
				t.Fatal("response direction/first-fragment timestamp lost")
			}
		})
	}
}

func TestSMB2TCPFramingAndAcknowledgementOrder(t *testing.T) {
	writes := append(smb2WritePair(2, 42, bind(1, uuidSVCCTL)), smb2WritePair(3, 42, request(2, 0, 12))...)
	for split := 0; split <= len(writes[0].Raw()); split++ {
		data := smb2Open("svcctl", 42)
		wire := writes[0].Raw()
		data = append(data, fragment(wire[:split], 20, false), fragment(wire[split:], 21, false), writes[2], writes[3], writes[1])
		data = append(data, smb2ReadPair(4, 42, response(ptypeResponse, 2, 0, 0))...)
		_, records := pipeRecords(data)
		if len(records) != 3 || records[1].OperationName != "RCreateServiceW" || records[2].OperationName != "RCreateServiceW" {
			t.Fatalf("split %d: %+v", split, records)
		}
		want := int64(20)
		if split == 0 {
			want = 21
		}
		if records[0].Timestamp != want {
			t.Fatalf("split %d timestamp %d", split, records[0].Timestamp)
		}
	}
}

func TestSMB2ScopesMultiplexingAndHandleReuse(t *testing.T) {
	data := smb2Open("svcctl", 42)
	data = append(data, smb2CreatePair(2, "samr", 43)...)
	data = append(data, smb2WritePair(3, 42, cat(bind(1, uuidSVCCTL), request(7, 0, 12)))...)
	data = append(data, smb2WritePair(4, 43, cat(bind(1, uuidSAMR), request(7, 0, 64)))...)
	oldRead := smb2ReadPair(5, 42, response(ptypeResponse, 7, 0, 0))
	data = append(data, oldRead[0])
	close := make([]byte, 24)
	close[8] = 42
	data = append(data, smb2Fragment(6, false, 6, close), smb2Fragment(6, true, 6, make([]byte, 60)))
	data = append(data, smb2CreatePair(7, "other", 42)...)
	data = append(data, smb2WritePair(8, 42, request(7, 0, 19))...)
	data = append(data, oldRead[1]) // reply is still for the old lifetime
	data = append(data, smb2ReadPair(9, 43, response(ptypeResponse, 7, 0, 0))...)
	pipes, _ := pipeRecords(data)
	if len(pipes) != 3 {
		t.Fatalf("pipe lifetimes %d", len(pipes))
	}
	a, b, c := decodeAll(pipes[0]), decodeAll(pipes[1]), decodeAll(pipes[2])
	if len(a) != 3 || a[2].OperationName != "RCreateServiceW" || len(b) != 3 || b[2].OperationName != "SamrConnect5" || len(c) != 1 || c[0].InterfaceName != "" || pipes[0].Ident == pipes[2].Ident {
		t.Fatal(a, b, c)
	}
	// Identical handles and MIDs in other sessions/trees must remain independent.
	for _, scope := range [][2]byte{{2, 1}, {1, 2}} {
		x := smb2Open("samr", 42)
		x = append(x, smb2WritePair(3, 42, cat(bind(1, uuidSAMR), request(7, 0, 64)))...)
		for _, f := range x {
			f.Raw()[44], f.Raw()[40] = scope[0], scope[1]
		}
		p, _ := pipeRecords(append(append(core.DataFragments{}, data...), x...))
		if len(p) != 4 || decodeAll(p[3])[1].OperationName != "SamrConnect5" {
			t.Fatal("cross-scope attribution", len(p))
		}
	}
}

func smb2Compound(frames ...[]byte) []byte {
	var out []byte
	for i, raw := range frames {
		b := append([]byte(nil), raw[4:]...)
		if i != 0 {
			b[16] |= 4
			for n := 36; n < 48; n++ {
				b[n] = 0xff
			}
		}
		if i+1 != len(frames) {
			b = append(b, make([]byte, (8-len(b)%8)%8)...)
			binary.LittleEndian.PutUint32(b[20:], uint32(len(b)))
		}
		out = append(out, b...)
	}
	return append([]byte{0, byte(len(out) >> 16), byte(len(out) >> 8), byte(len(out))}, out...)
}

func TestSMB2RelatedCompoundAndAsyncOverflow(t *testing.T) {
	data := smb2Open("existing", 41)[:2]
	create := smb2CreatePair(1, "svcctl", 42)
	write := smb2WritePair(2, 42, bind(1, uuidSVCCTL))
	ioctl := smb2IOCTLPair(3, 42, request(2, 0, 12), response(ptypeResponse, 2, 0, 0))
	for _, id := range [][]byte{write[0].Raw()[84:100], ioctl[0].Raw()[76:92]} {
		for i := range id {
			id[i] = 0xff
		}
	}
	data = append(data, fragment(smb2Compound(create[0].Raw(), write[0].Raw(), ioctl[0].Raw()), 10, false))
	data = append(data, fragment(smb2Compound(create[1].Raw(), write[1].Raw(), ioctl[1].Raw()), 20, true))
	p, recs := pipeRecords(data)
	if len(p) != 1 || len(recs) != 3 || recs[2].OperationName != "RCreateServiceW" {
		t.Fatal(p, recs)
	}
	read := smb2ReadPair(4, 42, response(ptypeResponse, 99, 0, 0))
	pending := smb2Fragment(8, true, 4, make([]byte, 8))
	binary.LittleEndian.PutUint32(pending.Raw()[12:], smbStatusPending)
	pending.Raw()[20] |= 2
	pending.Raw()[40] = 255
	read[1].Raw()[20] |= 2
	read[1].Raw()[40] = 255
	binary.LittleEndian.PutUint32(read[1].Raw()[12:], smbStatusOverflow)
	data = append(data, read[0], pending, read[1])
	_, recs = pipeRecords(data)
	if len(recs) != 4 || recs[3].InterfaceName != "SVCCTL" || recs[3].OperationName != "" {
		t.Fatal("async/orphan response", recs)
	}
}

func TestSMBPipeEvidenceBarriers(t *testing.T) {
	for _, mode := range []string{"disk", "missing-tree", "missing-create", "failed-create", "bad-name", "encrypted", "compressed", "gap", "short-write", "unacknowledged", "bad-offset", "wrong-command", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			data := smb2Open("samr", 42)
			data = append(data, smb2WritePair(2, 42, bind(1, uuidSAMR))...)
			more := smb2WritePair(3, 42, request(2, 0, 64))
			want := 1
			switch mode {
			case "disk":
				data[1].Raw()[70] = 1
				want = 0
			case "missing-tree":
				data = data[2:]
				want = 0
			case "missing-create":
				data = append(data[:2], data[4:]...)
				want = 0
			case "failed-create":
				binary.LittleEndian.PutUint32(data[3].Raw()[12:], 0xc0000022)
				want = 0
			case "bad-name":
				data[2].Raw()[124] = 0
				want = 0
			case "encrypted", "compressed":
				sig := byte(0xfd)
				if mode == "compressed" {
					sig = 0xfc
				}
				data = append(data, fragment(cat([]byte{0, 0, 0, 32, sig, 'S', 'M', 'B'}, make([]byte, 28)), 20, false))
			case "gap":
				data = append(data, &core.StreamData{SkippedBytes: 1})
			case "short-write":
				more[1].Raw()[72]--
			case "unacknowledged":
				more = more[:1]
			case "bad-offset":
				binary.LittleEndian.PutUint16(more[0].Raw()[70:], 64)
			case "wrong-command":
				binary.LittleEndian.PutUint16(more[1].Raw()[16:], 8)
			case "truncated":
				data = append(data, fragment(more[0].Raw()[:10], 30, false))
				more = nil
			}
			data = append(data, more...)
			_, records := pipeRecords(data)
			if len(records) != want {
				t.Fatalf("expected %d valid-prefix records, got %v", want, records)
			}
		})
	}
}

func TestSMB2PendingReadCannotCrossTreeReconnect(t *testing.T) {
	data := smb2Open("svcctl", 42)
	data = append(data, smb2WritePair(2, 42, bind(1, uuidSVCCTL))...)
	read := smb2ReadPair(3, 42, response(ptypeResponse, 7, 0, 0))
	data = append(data, read[0])
	reopen := smb2Open("samr", 42)
	data = append(data, reopen...)
	data = append(data, smb2WritePair(4, 42, cat(bind(1, uuidSAMR), request(7, 0, 64)))...)
	data = append(data, read[1])
	p, _ := pipeRecords(data)
	if len(p) != 2 || len(decodeAll(p[0])) != 1 || len(decodeAll(p[1])) != 2 {
		t.Fatal("reconnected tree accepted stale response", p)
	}
}

func FuzzSMBPipeTransport(f *testing.F) {
	data := smb2Open("svcctl", 42)
	data = append(data, smb2WritePair(2, 42, cat(bind(1, uuidSVCCTL), request(2, 0, 12)))...)
	var seed []byte
	for _, d := range data {
		dir := byte(0)
		if d.Direction() == reassembly.TCPDirServerToClient {
			dir = 1
		}
		seed = append(seed, dir)
		seed = binary.LittleEndian.AppendUint16(seed, uint16(len(d.Raw())))
		seed = append(seed, d.Raw()...)
	}
	f.Add(seed)
	seed = nil
	smb1 := smb1Open("svcctl", 42, true)
	smb1 = append(smb1, smb1TransRequest(2, 42, 0x26, bind(1, uuidSVCCTL), len(bind(1, uuidSVCCTL))), smb1TransReply(2, pdu(12, 3, 1, nil), 16, 0))
	for _, d := range smb1 {
		dir := byte(0)
		if d.Direction() == reassembly.TCPDirServerToClient {
			dir = 1
		}
		seed = append(seed, dir)
		seed = binary.LittleEndian.AppendUint16(seed, uint16(len(d.Raw())))
		seed = append(seed, d.Raw()...)
	}
	f.Add(seed)
	f.Add([]byte{0, 4, 0, 0, 255, 255, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 128<<10 {
			t.Skip()
		}
		var data core.DataFragments
		for len(b) >= 3 {
			n := min(int(binary.LittleEndian.Uint16(b[1:])), len(b)-3)
			d := fragment(b[3:3+n], 1, b[0]&1 != 0)
			if b[0]&2 != 0 {
				d.SkippedBytes = 1
			}
			data = append(data, d)
			b = b[3+n:]
		}
		pipes, _ := pipeRecords(data)
		if len(pipes) > smbPipeLifetimeLimit {
			t.Fatal("unbounded lifetimes")
		}
		for _, p := range pipes {
			if !strings.Contains(p.Ident, "|pipe:") || len(p.Data) > smbPipeFragmentLimit {
				t.Fatal("invalid pipe evidence")
			}
		}
	})
}

func TestSMBRPCFragmentedCalls(t *testing.T) {
	data := smb2Open("svcctl", 42)
	data = append(data, smb2WritePair(2, 42, bind(1, uuidSVCCTL))...)
	a, b := request(2, 0, 12), request(2, 0, 12)
	a[3], b[3] = 1, 2
	data = append(data, smb2WritePair(3, 42, a)...)
	data = append(data, smb2WritePair(4, 42, b)...)
	a, b = response(ptypeResponse, 2, 0, 0), response(ptypeResponse, 2, 0, 0)
	a[3], b[3] = 1, 2
	data = append(data, smb2ReadPair(5, 42, a)...)
	data = append(data, smb2ReadPair(6, 42, b)...)
	_, records := pipeRecords(data)
	if len(records) != 5 {
		t.Fatal(records)
	}
	for _, r := range records[1:] {
		if r.OperationName != "RCreateServiceW" || r.CallID != 2 {
			t.Fatal(r)
		}
	}
}

func TestSMB2IOCTLHandleAndCompoundBounds(t *testing.T) {
	for _, bad := range []string{"fid", "offset", "next", "related-first", "size"} {
		data := smb2Open("svcctl", 42)
		data = append(data, smb2WritePair(2, 42, bind(1, uuidSVCCTL))...)
		ioctl := smb2IOCTLPair(3, 42, request(2, 0, 12), response(ptypeResponse, 2, 0, 0))
		switch bad {
		case "fid":
			ioctl[1].Raw()[76]++
		case "offset":
			binary.LittleEndian.PutUint32(ioctl[1].Raw()[100:], uint32(len(ioctl[1].Raw())))
		case "next":
			binary.LittleEndian.PutUint32(ioctl[0].Raw()[24:], 63)
		case "related-first":
			ioctl[0].Raw()[20] |= 4
		case "size":
			ioctl[0].Raw()[68] = 0
		}
		data = append(data, ioctl...)
		_, records := pipeRecords(data)
		if len(records) != 1 {
			t.Fatal(bad, records)
		}
	}
}

func TestSMBPipeLimitsRetainQualifiedPrefix(t *testing.T) {
	for _, budget := range []string{"pending", "lifetimes", "bytes"} {
		t.Run(budget, func(t *testing.T) {
			data := smb2Open("svcctl", 42)
			data = append(data, smb2WritePair(2, 42, bind(1, uuidSVCCTL))...)
			switch budget {
			case "pending":
				for i := 0; i <= smbPipeStateLimit; i++ {
					data = append(data, smb2ReadPair(uint64(i+3), 42, []byte{0})[0])
				}
			case "lifetimes":
				for i := 0; i <= smbPipeLifetimeLimit; i++ {
					data = append(data, smb2CreatePair(uint64(i+3), "empty", 43)...)
				}
			case "bytes":
				for i := 0; i < 17; i++ {
					data = append(data, smb2WritePair(uint64(i+3), 42, make([]byte, 512<<10))...)
				}
			}
			pipes, records := pipeRecords(data)
			if len(records) != 1 || len(pipes) == 0 || !strings.Contains(pipes[0].Ident, "-limit") {
				t.Fatal("resource cutoff lost or fabricated evidence", len(records), pipes)
			}
		})
	}
}

func TestSMBPipeNameValidation(t *testing.T) {
	for _, s := range []string{"", "\\", "pipe\\", "a\\..\\b", "bad\x00name", "bad\nname", "disk/file", "file:stream"} {
		if smbPipeName(s) != "" {
			t.Fatalf("accepted %q", s)
		}
	}
	if smbPipeName("\\PIPE\\custom\\name") != "custom\\name" {
		t.Fatal("valid named pipe rejected")
	}
	if smbUnicode([]byte{0x00, 0xd8}) != "" || smbUnicode([]byte{0x00, 0xdc}) != "" || smbUnicode([]byte{1}) != "" {
		t.Fatal("malformed UTF-16 accepted")
	}
	if !bytes.Equal(smbWide("svcctl"), []byte{'s', 0, 'v', 0, 'c', 0, 'c', 0, 't', 0, 'l', 0}) {
		t.Fatal("fixture encoding")
	}
}
