package smb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

type smb1Files struct {
	pending map[string]smbFileRequest
	trees   map[string]string
	files   map[string]*smbTransfer
	stored  int
	emit    func(*smbTransfer, []byte)
}

func newSMB1Files(emit func(*smbTransfer, []byte)) *smb1Files {
	return &smb1Files{pending: map[string]smbFileRequest{}, trees: map[string]string{}, files: map[string]*smbTransfer{}, emit: emit}
}
func (s *smb1Files) publish(key string) {
	if t := s.files[key]; t != nil {
		if b, ok := completeSMBFile(t); ok {
			s.emit(t, b)
		}
		for _, c := range t.chunks {
			s.stored -= len(c.data)
		}
		delete(s.files, key)
	}
}
func (s *smb1Files) close() {
	keys := make([]string, 0, len(s.files))
	for key := range s.files {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		s.publish(key)
	}
}
func (s *smb1Files) chunk(t *smbTransfer, offset uint64, b []byte, direction string) {
	if t == nil || t.invalid || len(b) == 0 {
		return
	}
	if offset > maxSMBFile || len(b) > maxSMBFile-int(offset) || s.stored+len(b) > 64<<20 || len(t.chunks) >= 8192 {
		t.invalid = true
		return
	}
	t.chunks = append(t.chunks, smbChunk{offset, append([]byte(nil), b...)})
	t.direction = direction
	s.stored += len(b)
}

func (s *smb1Files) consume(frame []byte, at int64) {
	if len(frame) < 35 || !bytes.Equal(frame[:4], []byte{255, 'S', 'M', 'B'}) {
		return
	}
	command := frame[4]
	response := frame[9]&0x80 != 0
	status := binary.LittleEndian.Uint32(frame[5:])
	wc := int(frame[32])
	end := 33 + wc*2
	if end+2 > len(frame) {
		return
	}
	p := frame[33:end]
	count := int(binary.LittleEndian.Uint16(frame[end:]))
	if count > len(frame)-end-2 {
		return
	}
	start := end + 2
	data := frame[start : start+count]
	uid, tid, mid := binary.LittleEndian.Uint16(frame[28:]), binary.LittleEndian.Uint16(frame[24:]), binary.LittleEndian.Uint16(frame[30:])
	requestKey := fmt.Sprintf("%d:%d:%d", uid, mid, command)
	tree := fmt.Sprintf("%d:%d", uid, tid)
	fileKey := func(fid uint16) string { return tree + fmt.Sprintf(":%d", fid) }
	slice := func(offset, length uint32) []byte {
		if offset < uint32(start) || offset > uint32(len(frame)) || length > uint32(len(frame))-offset {
			return nil
		}
		return frame[offset : offset+length]
	}
	text := func(b []byte, absolute int) string {
		if binary.LittleEndian.Uint16(frame[10:])&0x8000 != 0 {
			if absolute%2 != 0 && len(b) > 0 {
				b = b[1:]
			}
			for i := 0; i+1 < len(b); i += 2 {
				if b[i] == 0 && b[i+1] == 0 {
					b = b[:i]
					break
				}
			}
			if len(b)%2 != 0 {
				b = b[:len(b)-1]
			}
			return smbText(b)
		}
		if index := bytes.IndexByte(b, 0); index >= 0 {
			b = b[:index]
		}
		return string(b)
	}
	if !response {
		if len(s.pending) >= 4096 {
			return
		}
		r := smbFileRequest{command: uint16(command), at: at, share: s.trees[tree]}
		switch command {
		case 0x75:
			if len(p) < 8 {
				return
			}
			password := int(binary.LittleEndian.Uint16(p[6:]))
			if password > len(data) {
				return
			}
			r.share = text(data[password:], start+password)
		case 0xa2:
			if len(p) < 48 {
				return
			}
			r.name = text(data, start)
			r.directory = binary.LittleEndian.Uint32(p[39:])&1 != 0
		case 0x2e:
			if len(p) < 20 {
				return
			}
			r.key = fileKey(binary.LittleEndian.Uint16(p[4:]))
			r.offset = uint64(binary.LittleEndian.Uint32(p[6:]))
			if len(p) >= 24 {
				r.offset |= uint64(binary.LittleEndian.Uint32(p[20:])) << 32
			}
		case 0x2f:
			if len(p) < 24 {
				return
			}
			r.key = fileKey(binary.LittleEndian.Uint16(p[4:]))
			r.offset = uint64(binary.LittleEndian.Uint32(p[6:]))
			if len(p) >= 28 {
				r.offset |= uint64(binary.LittleEndian.Uint32(p[24:])) << 32
			}
			n := uint32(binary.LittleEndian.Uint16(p[20:])) | uint32(binary.LittleEndian.Uint16(p[18:]))<<16
			b := slice(uint32(binary.LittleEndian.Uint16(p[22:])), n)
			if len(b) == 0 || s.stored+len(b) > 64<<20 {
				return
			}
			r.data = append([]byte(nil), b...)
			s.stored += len(b)
		case 4:
			if len(p) < 2 {
				return
			}
			r.key = fileKey(binary.LittleEndian.Uint16(p))
		default:
			return
		}
		if old, ok := s.pending[requestKey]; ok {
			s.stored -= len(old.data)
		}
		s.pending[requestKey] = r
		return
	}
	r, ok := s.pending[requestKey]
	if !ok {
		return
	}
	delete(s.pending, requestKey)
	s.stored -= len(r.data)
	if status != 0 {
		return
	}
	switch command {
	case 0x75:
		if len(s.trees) < 256 {
			s.trees[tree] = r.share
		}
	case 0xa2:
		if len(p) < 68 || r.directory || p[67] != 0 || binary.LittleEndian.Uint16(p[63:]) != 0 || r.name == "" || r.share == "" || strings.HasSuffix(strings.ToUpper(r.share), "\\IPC$") || len(s.files) >= 128 {
			return
		}
		key := fileKey(binary.LittleEndian.Uint16(p[5:]))
		s.publish(key)
		size := binary.LittleEndian.Uint64(p[55:])
		action := binary.LittleEndian.Uint32(p[7:])
		s.files[key] = &smbTransfer{name: r.name, share: r.share, size: size, sizeKnown: size > 0, created: size == 0 && action != 1, at: r.at}
	case 0x2e:
		if len(p) >= 16 {
			n := uint32(binary.LittleEndian.Uint16(p[10:])) | uint32(binary.LittleEndian.Uint16(p[14:]))<<16
			s.chunk(s.files[r.key], r.offset, slice(uint32(binary.LittleEndian.Uint16(p[12:])), n), "server_to_client")
		}
	case 0x2f:
		if len(p) >= 6 {
			count := uint32(binary.LittleEndian.Uint16(p[4:]))
			if len(p) >= 10 {
				count |= uint32(binary.LittleEndian.Uint16(p[8:])) << 16
			}
			if count <= uint32(len(r.data)) {
				s.chunk(s.files[r.key], r.offset, r.data[:count], "client_to_server")
			}
		}
	case 4:
		if t := s.files[r.key]; t != nil {
			if t.created {
				for _, c := range t.chunks {
					t.size = max(t.size, c.offset+uint64(len(c.data)))
				}
				t.sizeKnown = true
			}
			s.publish(r.key)
		}
	}
}
