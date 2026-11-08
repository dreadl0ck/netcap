package dcerpc

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

func smb1Frame(command byte, reply bool, mid uint16, params, data []byte, wide bool) []byte {
	b := make([]byte, 32)
	copy(b, "\xffSMB")
	b[4] = command
	b[24], b[26], b[28] = 1, 2, 3
	binary.LittleEndian.PutUint16(b[30:], mid)
	if reply {
		b[9] = 0x80
	}
	binary.LittleEndian.PutUint16(b[10:], 0x4000)
	if wide {
		b[11] |= 0x80
	}
	b = append(b, byte(len(params)/2))
	b = append(b, params...)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(data)))
	b = append(b, data...)
	return append([]byte{0, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b...)
}

func smb1Fragment(cmd byte, reply bool, mid uint16, p, data []byte) *core.StreamData {
	return fragment(smb1Frame(cmd, reply, mid, p, data, false), int64(mid)*100, reply)
}

func smb1Open(name string, fid uint16, wide bool) core.DataFragments {
	p := make([]byte, 48)
	p[0] = 0xff
	n := []byte(name)
	if wide {
		n = smbWide(name)
	}
	binary.LittleEndian.PutUint16(p[5:], uint16(len(n)))
	if wide {
		n = append([]byte{0}, n...)
	} // absolute data offset 83, align to 84
	r := make([]byte, 68)
	r[0], r[63] = 0xff, 2
	binary.LittleEndian.PutUint16(r[5:], fid)
	return core.DataFragments{fragment(smb1Frame(0xa2, false, 1, p, n, wide), 1, false), smb1Fragment(0xa2, true, 1, r, nil)}
}

func smb1WritePair(mid, fid uint16, data []byte, andx bool) core.DataFragments {
	p, r, cmd := make([]byte, 10), make([]byte, 2), byte(0x0b)
	var bytes []byte
	if andx {
		p, r, cmd = make([]byte, 28), make([]byte, 12), 0x2f
		p[0], r[0] = 0xff, 0xff
		binary.LittleEndian.PutUint16(p[4:], fid)
		binary.LittleEndian.PutUint16(p[20:], uint16(len(data)))
		binary.LittleEndian.PutUint16(p[22:], 64)
		binary.LittleEndian.PutUint16(r[4:], uint16(len(data)))
		bytes = append([]byte{0}, data...)
	} else {
		binary.LittleEndian.PutUint16(p, fid)
		binary.LittleEndian.PutUint16(p[2:], uint16(len(data)))
		binary.LittleEndian.PutUint16(r, uint16(len(data)))
		bytes = binary.LittleEndian.AppendUint16([]byte{1}, uint16(len(data)))
		bytes = append(bytes, data...)
	}
	return core.DataFragments{smb1Fragment(cmd, false, mid, p, bytes), smb1Fragment(cmd, true, mid, r, nil)}
}

func smb1ReadPair(mid, fid uint16, data []byte, andx bool) core.DataFragments {
	p, r, cmd := make([]byte, 10), make([]byte, 10), byte(0x0a)
	var bytes []byte
	if andx {
		p, r, cmd = make([]byte, 24), make([]byte, 24), 0x2e
		p[0], r[0] = 0xff, 0xff
		binary.LittleEndian.PutUint16(p[4:], fid)
		binary.LittleEndian.PutUint16(p[10:], uint16(len(data)))
		binary.LittleEndian.PutUint16(r[10:], uint16(len(data)))
		binary.LittleEndian.PutUint16(r[12:], 60)
		bytes = append([]byte{0}, data...)
	} else {
		binary.LittleEndian.PutUint16(p, fid)
		binary.LittleEndian.PutUint16(p[2:], uint16(len(data)))
		binary.LittleEndian.PutUint16(r, uint16(len(data)))
		bytes = binary.LittleEndian.AppendUint16([]byte{1}, uint16(len(data)))
		bytes = append(bytes, data...)
	}
	return core.DataFragments{smb1Fragment(cmd, false, mid, p, nil), smb1Fragment(cmd, true, mid, r, bytes)}
}

func smb1TransRequest(mid, fid, op uint16, data []byte, total int) *core.StreamData {
	p := make([]byte, 32)
	binary.LittleEndian.PutUint16(p[2:], uint16(total))
	binary.LittleEndian.PutUint16(p[6:], 65535)
	binary.LittleEndian.PutUint16(p[22:], uint16(len(data)))
	binary.LittleEndian.PutUint16(p[24:], 74) // data follows \PIPE\ NUL
	p[26] = 2
	binary.LittleEndian.PutUint16(p[28:], op)
	binary.LittleEndian.PutUint16(p[30:], fid)
	return smb1Fragment(0x25, false, mid, p, append([]byte("\\PIPE\\\x00"), data...))
}

func smb1TransSecondary(mid uint16, data []byte, total, offset int) *core.StreamData {
	p := make([]byte, 16)
	binary.LittleEndian.PutUint16(p[2:], uint16(total))
	binary.LittleEndian.PutUint16(p[10:], uint16(len(data)))
	binary.LittleEndian.PutUint16(p[12:], 51)
	binary.LittleEndian.PutUint16(p[14:], uint16(offset))
	return smb1Fragment(0x26, false, mid, p, data)
}

func smb1TransReply(mid uint16, data []byte, total, offset int) *core.StreamData {
	p := make([]byte, 20)
	binary.LittleEndian.PutUint16(p[2:], uint16(total))
	binary.LittleEndian.PutUint16(p[12:], uint16(len(data)))
	binary.LittleEndian.PutUint16(p[14:], 55)
	binary.LittleEndian.PutUint16(p[16:], uint16(offset))
	return smb1Fragment(0x25, true, mid, p, data)
}

func TestSMB1ReadWriteAndPipeResourceEvidence(t *testing.T) {
	for _, wide := range []bool{false, true} {
		for _, andx := range []bool{false, true} {
			data := smb1Open("\\lsarpc", 0x4001, wide)
			binding := bind(1, "12345778-1234-abcd-ef00-0123456789ab")
			data = append(data, smb1WritePair(2, 0x4001, binding[:9], andx)...)
			data = append(data, smb1WritePair(3, 0x4001, cat(binding[9:], request(2, 0, 44)), andx)...)
			reply := response(ptypeResponse, 2, 0, 0)
			data = append(data, smb1ReadPair(4, 0x4001, reply[:17], andx)...)
			data = append(data, smb1ReadPair(5, 0x4001, reply[17:], andx)...)
			pipes, records := pipeRecords(data)
			if len(pipes) != 1 || !strings.Contains(pipes[0].Ident, "pipe:lsarpc:") || len(records) != 3 || records[2].OperationName != "LsarOpenPolicy2" {
				t.Fatalf("wide=%v andx=%v %v", wide, andx, records)
			}
			// The same filename on a disk resource is not a named pipe.
			data[1].Raw()[4+33+63] = 0
			if p, _ := pipeRecords(data); len(p) != 0 {
				t.Fatal("disk bytes became RPC")
			}
		}
	}
}

func TestSMB1TransactionDisplacements(t *testing.T) {
	for _, bad := range []string{"", "hole", "conflict", "bad-offset", "changed-total", "missing-create", "response-hole", "response-conflict"} {
		t.Run(bad, func(t *testing.T) {
			data := smb1Open("\\svcctl", 42, true)
			data = append(data, smb1WritePair(2, 42, bind(1, uuidSVCCTL), true)...)
			req, reply := request(2, 0, 12), response(ptypeResponse, 2, 0, 0)
			primary := smb1TransRequest(3, 42, 0x26, req[:8], len(req))
			secondary := smb1TransSecondary(3, req[8:], len(req), 8)
			last := smb1TransReply(3, reply[:8], len(reply), 0)
			data = append(data, primary, smb1Fragment(0x25, true, 3, nil, nil))
			want := 3
			switch bad {
			case "hole":
				secondary = smb1TransSecondary(3, req[9:], len(req), 9)
				want = 1
			case "conflict":
				secondary = smb1TransSecondary(3, append([]byte{0xff}, req[8:]...), len(req), 7)
				want = 1
			case "bad-offset":
				binary.LittleEndian.PutUint16(secondary.Raw()[4+33+12:], 32)
				want = 1
			case "changed-total":
				secondary.Raw()[4+33+2]++
				want = 1
			case "missing-create":
				data = data[2:]
				want = 0
			case "response-hole":
				last = smb1TransReply(3, reply[:7], len(reply), 0)
				want = 1
			case "response-conflict":
				last = smb1TransReply(3, append(append([]byte(nil), reply[:8]...), 0xff), len(reply), 0)
				want = 1
			}
			// Response transaction fragments may arrive in displacement order 8,0.
			data = append(data, secondary, smb1TransReply(3, reply[8:], len(reply), 8), last)
			_, records := pipeRecords(data)
			if len(records) != want {
				t.Fatalf("want %d records, got %v", want, records)
			}
			if want == 3 && records[2].OperationName != "RCreateServiceW" {
				t.Fatal(records[2])
			}
		})
	}
}

func TestSMB1TransactionReadWriteAndScopedMID(t *testing.T) {
	data := smb1Open("svcctl", 42, false)
	binding := bind(1, uuidSVCCTL)
	data = append(data, smb1TransRequest(2, 42, 0x26, binding, len(binding)), smb1TransReply(2, pdu(12, 3, 1, nil), 16, 0))
	req := request(2, 0, 12)
	data = append(data, smb1WritePair(3, 42, req, false)...)
	r := response(ptypeResponse, 2, 0, 0)
	readReq := smb1TransRequest(4, 42, 0x36, nil, 0)
	readResp := smb1TransReply(4, r, len(r), 0)
	wrongPID := fragment(append([]byte(nil), readResp.Raw()...), 400, true)
	wrongPID.Raw()[4+26]++
	data = append(data, readReq, wrongPID, readResp)
	_, records := pipeRecords(data)
	if len(records) != 4 || records[3].OperationName != "RCreateServiceW" {
		t.Fatal(records)
	}
	// TID and UID are independently part of the request/handle scope.
	for _, off := range []int{24, 28} {
		readResp.Raw()[4+off]++
		_, records = pipeRecords(data)
		if len(records) != 3 {
			t.Fatal("cross-scope transaction response", records)
		}
		readResp.Raw()[4+off]--
	}
}

func TestSMB1TransactionWriteRequiresFullAcknowledgement(t *testing.T) {
	for _, short := range []bool{false, true} {
		data := smb1Open("svcctl", 42, false)
		binding := bind(1, uuidSVCCTL)
		data = append(data, smb1TransRequest(2, 42, 0x37, binding, len(binding)))
		params := make([]byte, 20)
		binary.LittleEndian.PutUint16(params, 2)
		binary.LittleEndian.PutUint16(params[6:], 2)
		binary.LittleEndian.PutUint16(params[8:], 55)
		n := len(binding)
		if short {
			n--
		}
		data = append(data, smb1Fragment(0x25, true, 2, params, binary.LittleEndian.AppendUint16(nil, uint16(n))))
		data = append(data, smb1WritePair(3, 42, request(2, 0, 12), true)...)
		_, records := pipeRecords(data)
		if (!short && (len(records) != 2 || records[1].OperationName != "RCreateServiceW")) || (short && len(records) != 0) {
			t.Fatal("short transaction write accepted", short, records)
		}
	}
}

func TestSMB1AndXCompoundOpenWrite(t *testing.T) {
	data := smb1Open("svcctl", 42, false)
	write := smb1WritePair(1, 42, cat(bind(1, uuidSVCCTL), request(2, 0, 12)), true)
	for side := 0; side < 2; side++ {
		a := append([]byte(nil), data[side].Raw()[4:]...)
		b := append([]byte(nil), write[side].Raw()[4+32:]...)
		a[33] = 0x2f
		binary.LittleEndian.PutUint16(a[35:], uint16(len(a)))
		if side == 0 {
			binary.LittleEndian.PutUint16(b[1+4:], 0xffff)
			binary.LittleEndian.PutUint16(b[1+22:], uint16(len(a)+32))
		}
		a = append(a, b...)
		data[side] = fragment(append([]byte{0, byte(len(a) >> 16), byte(len(a) >> 8), byte(len(a))}, a...), int64(side+1), side == 1)
	}
	_, records := pipeRecords(data)
	if len(records) != 2 || records[1].OperationName != "RCreateServiceW" {
		t.Fatal(records)
	}
}

func TestSMB1GeneralPipeInterfacesAndReuse(t *testing.T) {
	for _, tc := range []struct {
		name, uuid, iface string
		op                uint16
	}{
		{"samr", uuidSAMR, "SAMR", 64},
		{"lsarpc", "12345778-1234-abcd-ef00-0123456789ab", "LSARPC", 44},
		{"srvsvc", "4b324fc8-1670-01d3-1278-5a47bf6ee188", "SRVSVC", 15},
		{"spoolss", "12345678-1234-abcd-ef00-0123456789ab", "SPOOLSS", 1},
		{"svcctl", uuidSVCCTL, "SVCCTL", 12},
		{"custom-管道", "e3514235-4b06-11d1-ab04-00c04fc2dcd2", "DRSUAPI", 3},
	} {
		t.Run(tc.iface, func(t *testing.T) {
			data := smb1Open(tc.name, 42, true)
			data = append(data, smb1WritePair(2, 42, cat(bind(1, tc.uuid), request(7, 0, tc.op)), true)...)
			oldRead := smb1ReadPair(3, 42, response(ptypeResponse, 7, 0, 0), true)
			data = append(data, oldRead[0])
			// A new successful create with the same FID is a new RPC context.
			data = append(data, smb1Open("unbound", 42, false)...)
			data = append(data, smb1WritePair(4, 42, request(7, 0, 19), true)...)
			data = append(data, oldRead[1])
			pipes, _ := pipeRecords(data)
			if len(pipes) != 2 {
				t.Fatalf("lifetimes=%d", len(pipes))
			}
			a, b := decodeAll(pipes[0]), decodeAll(pipes[1])
			if len(a) != 3 || a[2].InterfaceName != tc.iface || a[2].OpNum != int32(tc.op) || len(b) != 1 || b[0].InterfaceName != "" {
				t.Fatal("RPC context crossed reused FID", a, b)
			}
		})
	}
}

func TestSMB1LegacyOpensRequirePipeEvidence(t *testing.T) {
	for _, command := range []byte{0x02, 0x2d} {
		for _, wide := range []bool{false, true} {
			for _, bad := range []string{"", "disk", "unterminated", "length", "failed"} {
				p, r := make([]byte, 4), make([]byte, 14)
				start := 39
				if command == 0x2d {
					p, r, start = make([]byte, 30), make([]byte, 30), 65
					p[0], r[0], r[4], r[18] = 0xff, 0xff, 42, 2
				} else {
					r[0] = 42
				}
				var name []byte
				if command == 0x02 {
					name = append(name, 4)
					start++
				}
				if wide {
					if start%2 != 0 {
						name = append(name, 0)
					}
					name = append(name, smbWide("\\svcctl")...)
				} else {
					name = append(name, []byte("\\svcctl")...)
				}
				if bad != "unterminated" {
					name = append(name, 0)
					if wide {
						name = append(name, 0)
					}
				}
				if bad == "length" {
					p = p[:len(p)-2]
				}
				tree := make([]byte, 8)
				tree[0] = 0xff
				treeReply := make([]byte, 6)
				treeReply[0] = 0xff
				service := []byte("IPC\x00")
				if bad == "disk" {
					service = []byte("A:\x00")
					if command == 0x2d {
						r[18] = 0
					}
				}
				data := core.DataFragments{smb1Fragment(0x75, false, 0, tree, nil), smb1Fragment(0x75, true, 0, treeReply, service),
					fragment(smb1Frame(command, false, 1, p, name, wide), 1, false), smb1Fragment(command, true, 1, r, nil)}
				if bad == "failed" {
					binary.LittleEndian.PutUint32(data[3].Raw()[9:], 0xc0000022)
				}
				data = append(data, smb1WritePair(2, 42, cat(bind(1, uuidSVCCTL), request(2, 0, 12)), true)...)
				_, records := pipeRecords(data)
				if bad == "" {
					if len(records) != 2 || records[1].OperationName != "RCreateServiceW" {
						t.Fatal(command, wide, records)
					}
				} else if len(records) != 0 {
					t.Fatal("invalid open became RPC", command, wide, bad, records)
				}
			}
		}
	}
}

func TestSMB1DOSMoreDataAndGapBarrier(t *testing.T) {
	data := smb1Open("svcctl", 42, true)
	data = append(data, smb1WritePair(2, 42, cat(bind(1, uuidSVCCTL), request(2, 0, 12)), true)...)
	reply := response(ptypeResponse, 2, 0, 0)
	first, last := smb1ReadPair(3, 42, reply[:19], true), smb1ReadPair(4, 42, reply[19:], true)
	first[1].Raw()[15] &^= 0x40 // Flags2: DOS error instead of NT status
	first[1].Raw()[9], first[1].Raw()[11] = 1, 234
	data = append(data, first...)
	_, records := pipeRecords(append(append(core.DataFragments{}, data...), last...))
	if len(records) != 3 || records[2].OperationName != "RCreateServiceW" {
		t.Fatal("lost DOS partial pipe read", records)
	}
	data = append(data, &core.StreamData{SkippedBytes: 1})
	data = append(data, last...)
	_, records = pipeRecords(data)
	if len(records) != 2 {
		t.Fatal("RPC body crossed TCP gap", records)
	}
}
