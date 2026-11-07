package dcerpc

import (
	"bytes"
	"encoding/binary"

	"github.com/dreadl0ck/netcap/internal/reassembly"
)

// SMB1 transaction displacements are relative to the transaction, not the SMB
// message. Keep coverage and reject conflicting overlaps before exposing bytes.
type smbPipeAssembly struct {
	data, seen []byte
	count      int
	at         int64
}

type smbPipeTransaction struct {
	operation uint16
	in, out   *smbPipeAssembly
	sent      bool
}

func (t *smbPipeTransport) assemble(a **smbPipeAssembly, total, offset uint16, data []byte, at int64) bool {
	if int(offset)+len(data) > int(total) {
		return false
	}
	if *a == nil {
		if t.stored+2*int(total) > smbPipeByteLimit {
			t.stop = "byte-limit"
			return false
		}
		t.stored += 2 * int(total)
		*a = &smbPipeAssembly{data: make([]byte, total), seen: make([]byte, total), at: at}
	}
	b := *a
	if len(b.data) != int(total) {
		return false
	}
	for i, v := range data {
		at := int(offset) + i
		if b.seen[at] != 0 && b.data[at] != v {
			return false
		}
		if b.seen[at] == 0 {
			b.count++
			b.seen[at] = 1
			b.data[at] = v
		}
	}
	return true
}

func smb1Parts(frame []byte, at int) (params, data []byte, start, end int, ok bool) {
	if at < 32 || at >= len(frame) {
		return
	}
	n := int(frame[at]) * 2
	start = at + 1 + n + 2
	if start > len(frame) {
		return
	}
	end = start + int(binary.LittleEndian.Uint16(frame[start-2:]))
	if end > len(frame) {
		return
	}
	return frame[at+1 : start-2], frame[start:end], start, end, true
}

func smb1AndX(command byte) bool {
	switch command {
	case 0x73, 0x74, 0x75, 0xa2, 0x2d, 0x2e, 0x2f, 0x24:
		return true
	}
	return false
}

func (t *smbPipeTransport) smb1(frame []byte, dir reassembly.TCPFlowDirection, at int64) {
	if len(frame) < 35 {
		t.stop = "invalid-smb1"
		return
	}
	response := frame[9]&0x80 != 0
	if response != (dir == reassembly.TCPDirServerToClient) {
		t.stop = "direction-mismatch"
		return
	}
	status := binary.LittleEndian.Uint32(frame[5:])
	// Legacy servers report a partial pipe read as ERRDOS/ERRmoredata.
	if binary.LittleEndian.Uint16(frame[10:])&0x4000 == 0 && frame[5] == 1 && binary.LittleEndian.Uint16(frame[7:]) == 234 {
		status = smbStatusOverflow
	}
	scope := smbPipeScope{1, uint64(binary.LittleEndian.Uint16(frame[28:])), uint32(binary.LittleEndian.Uint16(frame[24:]))}
	pid := uint32(binary.LittleEndian.Uint16(frame[26:])) | uint32(binary.LittleEndian.Uint16(frame[12:]))<<16
	unicode := binary.LittleEndian.Uint16(frame[10:])&0x8000 != 0
	command, offset := frame[4], 32
	var created *smbPipe
	for steps := 0; steps < 64 && t.stop == ""; steps++ {
		t.sequence++
		p, data, start, end, ok := smb1Parts(frame, offset)
		if !ok {
			t.stop = "invalid-smb1-body"
			return
		}
		mid := smbPipeMID{version: 1, session: scope.session, mid: uint64(binary.LittleEndian.Uint16(frame[30:])), pid: pid, tree: scope.tree, command: uint16(command)}
		if command == 0x75 {
			mid.tree = 0
		}
		if command == 0x26 {
			mid.command = 0x25
		}
		lookup := func(id []byte) *smbPipe {
			if binary.LittleEndian.Uint16(id) == 0xffff && created != nil {
				return created
			}
			return t.handles[smbHandle(scope, id)]
		}
		payload := func(off, n uint16) []byte { return smbSlice(frame[:end], uint32(off), uint32(n), start) }
		if !response {
			r := &smbPipeRequest{scope: scope, at: at, sequence: t.sequence}
			switch command {
			case 0x75:
				if len(p) >= 8 {
					t.remember(mid, r)
				}
			case 0xa2:
				if len(p) != 48 {
					t.stop = "invalid-smb1-create"
					break
				}
				r.name = smbPipeName(smb1PipeCreateName(p, data, start, unicode))
				// SMB1 CREATE responses also carry a pipe resource type, so a
				// missing TREE_CONNECT need not prevent a later proven open.
				if r.name != "" && binary.LittleEndian.Uint32(p[39:])&1 == 0 {
					r.pipe = t.newPipe(scope, r.name)
				}
				created = r.pipe
				t.remember(mid, r)
			case 0x2d, 0x02: // OPEN_ANDX and legacy OPEN
				if (command == 0x2d && len(p) != 30) || (command == 0x02 && len(p) != 4) {
					t.stop = "invalid-smb1-open"
					break
				}
				if command == 0x02 {
					if len(data) == 0 || data[0] != 4 {
						break
					}
					data, start = data[1:], start+1
				}
				r.name = smbPipeName(smb1PipeTerminatedName(data, start, unicode))
				if r.name != "" && (command == 0x2d || t.trees[scope]) {
					r.pipe = t.newPipe(scope, r.name)
				}
				created = r.pipe
				t.remember(mid, r)
			case 0x2e, 0x2f:
				if (command == 0x2e && len(p) != 20 && len(p) != 24) || (command == 0x2f && len(p) != 24 && len(p) != 28) {
					t.stop = "invalid-smb1-io"
					break
				}
				r.pipe = lookup(p[4:6])
				if r.pipe == nil {
					break
				}
				if command == 0x2f {
					n := uint32(binary.LittleEndian.Uint16(p[20:])) | uint32(binary.LittleEndian.Uint16(p[18:]))<<16
					b := smbSlice(frame[:end], uint32(binary.LittleEndian.Uint16(p[22:])), n, start)
					if uint32(len(b)) != n {
						t.fail(r, "invalid-write")
						break
					}
					r.data = t.hold(b)
				} else {
					r.limit = uint32(binary.LittleEndian.Uint16(p[10:]))
				}
				t.remember(mid, r)
			case 0x0a, 0x0b:
				if len(p) != 10 {
					t.stop = "invalid-smb1-io"
					break
				}
				r.pipe = lookup(p[:2])
				if r.pipe == nil {
					break
				}
				r.limit = uint32(binary.LittleEndian.Uint16(p[2:]))
				if command == 0x0b {
					if len(data) < 3 || data[0] != 1 || uint32(binary.LittleEndian.Uint16(data[1:])) != r.limit || int(r.limit) != len(data)-3 {
						t.fail(r, "invalid-write")
						break
					}
					r.data = t.hold(data[3:])
				}
				t.remember(mid, r)
			case 4:
				if len(p) == 6 {
					r.pipe = lookup(p[:2])
					if r.pipe != nil {
						t.remember(mid, r)
					}
				}
			case 0x71, 0x74:
				t.forget(scope, command == 0x74)
			case 0x25:
				if len(p) != 32 || p[26] != 2 {
					break
				}
				op := binary.LittleEndian.Uint16(p[28:])
				if op != 0x26 && op != 0x36 && op != 0x37 {
					break
				}
				r.pipe = lookup(p[30:32])
				if r.pipe == nil {
					break
				}
				r.trans = &smbPipeTransaction{operation: op}
				r.limit = uint32(binary.LittleEndian.Uint16(p[6:]))
				n := binary.LittleEndian.Uint16(p[22:])
				b := payload(binary.LittleEndian.Uint16(p[24:]), n)
				if len(b) != int(n) || !t.assemble(&r.trans.in, binary.LittleEndian.Uint16(p[2:]), 0, b, at) {
					t.fail(r, "invalid-transaction")
					break
				}
				t.remember(mid, r)
			case 0x26:
				r = t.pending[mid]
				if r == nil || r.trans == nil {
					break
				}
				if len(p) != 16 {
					t.fail(r, "invalid-transaction")
					delete(t.pending, mid)
					break
				}
				n := binary.LittleEndian.Uint16(p[10:])
				b := payload(binary.LittleEndian.Uint16(p[12:]), n)
				if len(b) != int(n) || !t.assemble(&r.trans.in, binary.LittleEndian.Uint16(p[2:]), binary.LittleEndian.Uint16(p[14:]), b, at) {
					t.fail(r, "invalid-transaction")
					delete(t.pending, mid)
				}
			case 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x2c:
				// Raw/MPX transports have different framing. Never stitch a pipe
				// across data that this adapter cannot account for.
				t.stop = "unsupported-smb1-io"
			}
		} else if r := t.pending[mid]; r != nil {
			if status != smbStatusPending {
				if command == 0x25 && (status == 0 || status == smbStatusOverflow) {
					t.smb1TransactionReply(mid, r, p, payload, at)
				} else {
					delete(t.pending, mid)
					if status == 0 || (status == smbStatusOverflow && (command == 0x0a || command == 0x2e)) {
						switch command {
						case 0x75:
							if len(p) >= 6 {
								t.tree(scope, bytes.HasPrefix(data, []byte("IPC\x00")))
							}
						case 0xa2:
							if len(p) >= 68 {
								kind := binary.LittleEndian.Uint16(p[63:])
								if (kind != 1 && kind != 2) || p[67] != 0 {
									r.pipe = nil
								}
								t.bindHandle(scope, p[5:7], r.pipe)
							} else {
								t.stop = "invalid-smb1-create"
							}
						case 0x2d:
							if len(p) != 30 {
								t.stop = "invalid-smb1-open"
								break
							}
							kind := binary.LittleEndian.Uint16(p[18:])
							if (kind != 1 && kind != 2) || binary.LittleEndian.Uint16(p[6:])&0x10 != 0 {
								r.pipe = nil
							}
							t.bindHandle(scope, p[4:6], r.pipe)
						case 0x02:
							if len(p) != 14 {
								t.stop = "invalid-smb1-open"
								break
							}
							t.bindHandle(scope, p[:2], r.pipe)
						case 0x2e:
							if len(p) >= 24 {
								n := uint32(binary.LittleEndian.Uint16(p[10:])) | uint32(binary.LittleEndian.Uint16(p[14:]))<<16
								b := smbSlice(frame[:end], uint32(binary.LittleEndian.Uint16(p[12:])), n, start)
								if uint32(len(b)) == n && n <= r.limit {
									t.emit(r.pipe, t.hold(b), dir, at)
								} else {
									t.fail(r, "invalid-read")
								}
							} else {
								t.fail(r, "invalid-read")
							}
						case 0x0a:
							if len(p) == 10 && len(data) >= 3 && data[0] == 1 {
								n := int(binary.LittleEndian.Uint16(data[1:]))
								if n == len(data)-3 && n == int(binary.LittleEndian.Uint16(p)) && uint32(n) <= r.limit {
									t.emit(r.pipe, t.hold(data[3:]), dir, at)
								} else {
									t.fail(r, "invalid-read")
								}
							} else {
								t.fail(r, "invalid-read")
							}
						case 0x0b, 0x2f:
							count := -1
							if command == 0x0b && len(p) == 2 {
								count = int(binary.LittleEndian.Uint16(p))
							}
							if command == 0x2f && len(p) == 12 {
								count = int(binary.LittleEndian.Uint16(p[4:])) | int(binary.LittleEndian.Uint16(p[8:]))<<16
							}
							if count == len(r.data) {
								t.emit(r.pipe, r.data, reassembly.TCPDirClientToServer, r.at, r.sequence)
							} else {
								t.fail(r, "short-write")
							}
						case 4:
							t.closePipe(r.pipe, "")
						}
					} else if command == 0x2e || command == 0x0a || command == 0x2f || command == 0x0b || command == 0x25 {
						t.fail(r, "failed-io")
					}
				}
			}
		}
		if !smb1AndX(command) || len(p) < 4 || p[0] == 0xff {
			return
		}
		next := int(binary.LittleEndian.Uint16(p[2:]))
		if next < end || next <= offset || next >= len(frame) {
			t.stop = "invalid-andx"
			return
		}
		command, offset = p[0], next
	}
	if t.stop == "" {
		t.stop = "andx-limit"
	}
}

func (t *smbPipeTransport) smb1TransactionReply(mid smbPipeMID, r *smbPipeRequest, p []byte, payload func(uint16, uint16) []byte, at int64) {
	if len(p) == 0 {
		return
	} // interim response, waiting for secondaries
	tr := r.trans
	if tr == nil {
		return
	}
	bad := func() { t.fail(r, "invalid-transaction"); delete(t.pending, mid) }
	if len(p) < 20 || len(p) != 20+int(p[18])*2 || tr.in == nil || tr.in.count != len(tr.in.data) || uint32(binary.LittleEndian.Uint16(p[2:])) > r.limit {
		bad()
		return
	}
	if tr.operation == 0x37 {
		written := payload(binary.LittleEndian.Uint16(p[8:]), binary.LittleEndian.Uint16(p[6:]))
		if binary.LittleEndian.Uint16(p) != 2 || binary.LittleEndian.Uint16(p[10:]) != 0 || len(written) != 2 || int(binary.LittleEndian.Uint16(written)) != len(tr.in.data) {
			bad()
			return
		}
	}
	n := binary.LittleEndian.Uint16(p[12:])
	b := payload(binary.LittleEndian.Uint16(p[14:]), n)
	if len(b) != int(n) || !t.assemble(&tr.out, binary.LittleEndian.Uint16(p[2:]), binary.LittleEndian.Uint16(p[16:]), b, at) {
		bad()
		return
	}
	if !tr.sent {
		if tr.operation != 0x36 {
			t.emit(r.pipe, tr.in.data, reassembly.TCPDirClientToServer, tr.in.at, r.sequence)
		}
		tr.sent = true
	}
	if tr.out.count == len(tr.out.data) {
		if tr.operation != 0x37 {
			t.emit(r.pipe, tr.out.data, reassembly.TCPDirServerToClient, tr.out.at)
		}
		delete(t.pending, mid)
	}
}

func smb1PipeCreateName(p, data []byte, start int, unicode bool) string {
	n := int(binary.LittleEndian.Uint16(p[5:]))
	if unicode && start%2 != 0 {
		if len(data) == 0 {
			return ""
		}
		data = data[1:]
	}
	if n == 0 || n > len(data) {
		return ""
	}
	data = data[:n]
	if unicode {
		return smbUnicode(data)
	}
	for _, c := range data {
		if c < 0x20 || c > 0x7e {
			return ""
		}
	}
	return string(data)
}

func smb1PipeTerminatedName(data []byte, start int, unicode bool) string {
	if unicode && start%2 != 0 {
		if len(data) == 0 {
			return ""
		}
		data = data[1:]
	}
	width := 1
	if unicode {
		width = 2
	}
	for i := 0; i+width <= len(data); i += width {
		if data[i] != 0 || (unicode && data[i+1] != 0) {
			continue
		}
		if unicode {
			return smbUnicode(data[:i])
		}
		for _, c := range data[:i] {
			if c < 0x20 || c > 0x7e {
				return ""
			}
		}
		return string(data[:i])
	}
	return ""
}
