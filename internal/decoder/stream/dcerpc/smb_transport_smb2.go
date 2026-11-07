package dcerpc

import (
	"bytes"
	"encoding/binary"

	"github.com/dreadl0ck/netcap/internal/reassembly"
)

func (t *smbPipeTransport) smb2(message []byte, dir reassembly.TCPFlowDirection, at int64) {
	var previous smbPipeScope
	var created *smbPipe
	first := true
	for len(message) > 0 && t.stop == "" {
		t.sequence++
		if len(message) < 64 || string(message[:4]) != "\xfeSMB" || binary.LittleEndian.Uint16(message[4:]) != 64 {
			t.stop = "invalid-smb2"
			return
		}
		next := int(binary.LittleEndian.Uint32(message[20:]))
		frame := message
		if next != 0 {
			if next < 64 || next%8 != 0 || next > len(message)-64 {
				t.stop = "invalid-compound"
				return
			}
			frame = message[:next]
		}
		flags := binary.LittleEndian.Uint32(frame[16:])
		response := flags&1 != 0
		if response != (dir == reassembly.TCPDirServerToClient) {
			t.stop = "direction-mismatch"
			return
		}
		scope := smbPipeScope{2, binary.LittleEndian.Uint64(frame[40:]), binary.LittleEndian.Uint32(frame[36:])}
		related := flags&4 != 0
		if related {
			if first || flags&2 != 0 {
				t.stop = "invalid-related"
				return
			}
			// Related operations use the preceding effective session and tree.
			scope = previous
		} else {
			created = nil
		}
		command := binary.LittleEndian.Uint16(frame[12:])
		mid := smbPipeMID{version: 2, session: scope.session, mid: binary.LittleEndian.Uint64(frame[24:]), command: command}
		body := frame[64:]
		valid := func(size uint16, length int) bool {
			if len(body) < length || binary.LittleEndian.Uint16(body) != size {
				t.stop = "invalid-smb2-body"
				return false
			}
			return true
		}
		lookup := func(id []byte) *smbPipe {
			if related && bytes.Equal(id, bytes.Repeat([]byte{0xff}, 16)) {
				return created
			}
			return t.handles[smbHandle(scope, id)]
		}
		if !response {
			r := &smbPipeRequest{scope: scope, at: at, sequence: t.sequence}
			switch command {
			case 3: // TREE_CONNECT: the response's ShareType is authoritative.
				if !valid(9, 8) {
					break
				}
				t.remember(mid, r)
			case 5:
				if !valid(57, 56) {
					break
				}
				r.name = smbPipeName(smbUnicode(smbSlice(frame, uint32(binary.LittleEndian.Uint16(body[44:])), uint32(binary.LittleEndian.Uint16(body[46:])), 120)))
				if t.trees[scope] && r.name != "" && binary.LittleEndian.Uint32(body[40:])&1 == 0 {
					r.pipe = t.newPipe(scope, r.name)
				}
				created = r.pipe
				t.remember(mid, r)
			case 8, 9:
				if !valid(49, 48) {
					break
				}
				r.pipe = lookup(body[16:32])
				r.limit = binary.LittleEndian.Uint32(body[4:])
				if r.pipe == nil {
					break
				}
				if command == 9 {
					data := smbSlice(frame, uint32(binary.LittleEndian.Uint16(body[2:])), r.limit, 112)
					if uint32(len(data)) != r.limit {
						t.fail(r, "invalid-write")
						break
					}
					r.data = t.hold(data)
				}
				t.remember(mid, r)
			case 11:
				if !valid(57, 56) || binary.LittleEndian.Uint32(body[4:]) != 0x11c017 || binary.LittleEndian.Uint32(body[48:]) != 1 {
					break
				}
				r.pipe = lookup(body[8:24])
				if r.pipe == nil {
					break
				}
				count := binary.LittleEndian.Uint32(body[28:])
				data := smbSlice(frame, binary.LittleEndian.Uint32(body[24:]), count, 120)
				if uint32(len(data)) != count {
					t.fail(r, "invalid-ioctl")
					break
				}
				r.data = t.hold(data)
				r.limit = binary.LittleEndian.Uint32(body[44:])
				t.remember(mid, r)
			case 6:
				if valid(24, 24) {
					r.pipe = lookup(body[8:24])
					if r.pipe != nil {
						t.remember(mid, r)
					}
				}
			case 2, 4:
				if valid(4, 4) {
					t.forget(scope, command == 2)
				}
			}
		} else {
			status := binary.LittleEndian.Uint32(frame[8:])
			r := t.pending[mid]
			if r != nil && status != smbStatusPending {
				delete(t.pending, mid)
				if command != 3 && flags&2 == 0 && r.scope != scope {
					t.stop = "scope-mismatch"
					return
				}
				if status == 0 || (status == smbStatusOverflow && (command == 8 || command == 11)) {
					switch command {
					case 3:
						if valid(16, 16) {
							t.tree(scope, body[2] == 2)
						}
					case 5:
						if valid(89, 88) {
							if binary.LittleEndian.Uint32(body[56:])&0x10 != 0 {
								r.pipe = nil
							}
							t.bindHandle(r.scope, body[64:80], r.pipe)
						}
					case 6:
						if valid(60, 60) {
							t.closePipe(r.pipe, "")
						}
					case 8:
						if valid(17, 16) {
							count := binary.LittleEndian.Uint32(body[4:])
							data := smbSlice(frame, uint32(body[2]), count, 80)
							if count <= r.limit && uint32(len(data)) == count {
								t.emit(r.pipe, t.hold(data), dir, at)
							} else {
								t.fail(r, "invalid-read")
							}
						} else {
							t.fail(r, "invalid-read")
						}
					case 9:
						if valid(17, 16) && binary.LittleEndian.Uint32(body[4:]) == uint32(len(r.data)) {
							t.emit(r.pipe, r.data, reassembly.TCPDirClientToServer, r.at, r.sequence)
						} else {
							t.fail(r, "short-write")
						}
					case 11:
						if valid(49, 48) && binary.LittleEndian.Uint32(body[4:]) == 0x11c017 && r.pipe != nil && bytes.Equal(body[8:24], r.pipe.id[:]) {
							count := binary.LittleEndian.Uint32(body[36:])
							data := smbSlice(frame, binary.LittleEndian.Uint32(body[32:]), count, 112)
							if count <= r.limit && uint32(len(data)) == count {
								t.emit(r.pipe, r.data, reassembly.TCPDirClientToServer, r.at, r.sequence)
								t.emit(r.pipe, t.hold(data), dir, at)
							} else {
								t.fail(r, "invalid-ioctl")
							}
						} else {
							t.fail(r, "invalid-ioctl")
						}
					}
				} else if command == 8 || command == 9 || command == 11 {
					t.fail(r, "failed-io")
				}
			}
		}
		first, previous = false, scope
		if next == 0 {
			return
		}
		message = message[next:]
	}
}
