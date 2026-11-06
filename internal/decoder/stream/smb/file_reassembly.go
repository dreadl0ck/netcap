package smb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

const maxSMBFile = 32 << 20

type smbChunk struct {
	offset uint64
	data   []byte
}
type smbTransfer struct {
	name, share        string
	size               uint64
	sizeKnown, created bool
	chunks             []smbChunk
	at                 int64
	direction          string
	invalid            bool
}
type smbFileRequest struct {
	at               int64
	command          uint16
	key, name, share string
	offset           uint64
	data             []byte
	directory        bool
}

func smbText(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

// Only complete, consistent byte coverage is published as a reconstructed file.
func completeSMBFile(t *smbTransfer) ([]byte, bool) {
	if t.invalid || !t.sizeKnown || t.size == 0 || t.size > maxSMBFile {
		return nil, false
	}
	sort.SliceStable(t.chunks, func(i, j int) bool { return t.chunks[i].offset < t.chunks[j].offset })
	var out []byte
	for _, c := range t.chunks {
		if c.offset > uint64(len(out)) || c.offset > t.size || uint64(len(c.data)) > t.size-c.offset {
			return nil, false
		}
		overlap := min(len(c.data), len(out)-int(c.offset))
		if !bytes.Equal(out[int(c.offset):int(c.offset)+overlap], c.data[:overlap]) {
			return nil, false
		}
		out = append(out, c.data[overlap:]...)
	}
	return out, uint64(len(out)) == t.size
}

func extractSMBFiles(c *core.ConversationInfo, emit func(*smbTransfer, []byte)) {
	legacy := newSMB1Files(emit)
	defer legacy.close()
	var buffers [2][]byte
	requests := map[string]smbFileRequest{}
	trees := map[string]string{}
	files := map[string]*smbTransfer{}
	stored := 0
	publish := func(key string) {
		if t := files[key]; t != nil {
			if data, ok := completeSMBFile(t); ok {
				emit(t, data)
			}
			for _, chunk := range t.chunks {
				stored -= len(chunk.data)
			}
			delete(files, key)
		}
	}
	defer func() {
		keys := make([]string, 0, len(files))
		for k := range files {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			publish(k)
		}
	}()
	appendChunk := func(t *smbTransfer, offset uint64, data []byte, at int64, direction string) {
		if t == nil || t.invalid || len(data) == 0 {
			return
		}
		if offset > maxSMBFile || len(data) > maxSMBFile-int(offset) || stored+len(data) > 64<<20 || len(t.chunks) >= 8192 {
			t.invalid = true
			return
		}
		t.chunks = append(t.chunks, smbChunk{offset, append([]byte(nil), data...)})
		stored += len(data)
		if t.at == 0 {
			t.at = at
		}
		t.direction = direction
	}
	for _, fragment := range c.Data {
		side := 0
		if fragment.Direction() == reassembly.TCPDirServerToClient {
			side = 1
		}
		if f, ok := fragment.(*core.StreamData); ok && f.SkippedBytes != 0 && (f.SkippedBytes > 0 || len(buffers[side]) > 0) {
			return
		}
		if len(buffers[side])+len(fragment.Raw()) > 2<<20 {
			return
		}
		buffers[side] = append(buffers[side], fragment.Raw()...)
		for len(buffers[side]) >= 4 {
			b := buffers[side]
			n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
			if b[0] != 0 || n > 1<<20 {
				return
			}
			if len(b) < n+4 {
				break
			}
			message := b[4 : 4+n]
			legacy.consume(message, core.FragmentTime(fragment))
			for len(message) >= 64 && bytes.Equal(message[:4], []byte{0xfe, 'S', 'M', 'B'}) {
				if binary.LittleEndian.Uint16(message[4:]) != 64 {
					return
				}
				next := int(binary.LittleEndian.Uint32(message[20:]))
				frame := message
				if next != 0 {
					if next < 64 || next > len(message) {
						return
					}
					frame = message[:next]
				}
				body := frame[64:]
				command := binary.LittleEndian.Uint16(frame[12:])
				response := binary.LittleEndian.Uint32(frame[16:])&1 != 0
				status := binary.LittleEndian.Uint32(frame[8:])
				session := fmt.Sprintf("%x", frame[40:48])
				tree := session + fmt.Sprintf(":%x", frame[36:40])
				mid := session + fmt.Sprintf(":%x", frame[24:32])
				slice := func(off, count uint32) []byte {
					if off < 64 || off > uint32(len(frame)) || count > uint32(len(frame))-off {
						return nil
					}
					return frame[off : off+count]
				}
				fid := func(raw []byte) string { return tree + fmt.Sprintf(":%x", raw) }
				if !response && len(requests) < 4096 {
					r := smbFileRequest{command: command, share: trees[tree], at: core.FragmentTime(fragment)}
					switch command {
					case SMB2_TREE_CONNECT:
						if len(body) >= 8 {
							r.share = smbText(slice(uint32(binary.LittleEndian.Uint16(body[4:])), uint32(binary.LittleEndian.Uint16(body[6:]))))
						}
					case SMB2_CREATE:
						if len(body) >= 56 && binary.LittleEndian.Uint16(body[44:]) >= 120 {
							r.name = smbText(slice(uint32(binary.LittleEndian.Uint16(body[44:])), uint32(binary.LittleEndian.Uint16(body[46:]))))
							r.directory = binary.LittleEndian.Uint32(body[40:])&1 != 0
						}
					case SMB2_READ, SMB2_WRITE:
						if len(body) >= 32 {
							r.key = fid(body[16:32])
							r.offset = binary.LittleEndian.Uint64(body[8:])
							if command == SMB2_WRITE && len(body) >= 48 && binary.LittleEndian.Uint16(body[2:]) >= 112 {
								r.data = slice(uint32(binary.LittleEndian.Uint16(body[2:])), binary.LittleEndian.Uint32(body[4:]))
								if len(r.data) <= maxSMBFile && stored+len(r.data) <= 64<<20 {
									r.data = append([]byte(nil), r.data...)
									stored += len(r.data)
								} else {
									r.data = nil
								}
							}
						}
					case SMB2_CLOSE:
						if len(body) >= 24 {
							r.key = fid(body[8:24])
						}
					default:
						goto advance
					}
					requests[mid] = r
				} else if response {
					r, ok := requests[mid]
					if ok {
						delete(requests, mid)
						stored -= len(r.data)
					}
					if ok && r.command == command && status == 0 {
						switch command {
						case SMB2_TREE_CONNECT:
							if len(trees) < 256 {
								trees[tree] = r.share
							}
						case SMB2_CREATE:
							if len(body) >= 80 && binary.LittleEndian.Uint32(body[56:])&0x10 == 0 && r.name != "" && r.share != "" && !r.directory && !strings.HasSuffix(strings.ToUpper(r.share), "\\IPC$") && len(files) < 128 {
								key := fid(body[64:80])
								if files[key] != nil {
									publish(key)
								}
								size := binary.LittleEndian.Uint64(body[48:])
								action := binary.LittleEndian.Uint32(body[4:])
								files[key] = &smbTransfer{name: r.name, share: r.share, size: size, sizeKnown: size > 0, created: size == 0 && action != 1, at: r.at}
							}
						case SMB2_READ:
							if len(body) >= 16 && body[2] >= 80 {
								appendChunk(files[r.key], r.offset, slice(uint32(body[2]), binary.LittleEndian.Uint32(body[4:])), core.FragmentTime(fragment), "server_to_client")
							}
						case SMB2_WRITE:
							if len(body) >= 8 {
								count := int(binary.LittleEndian.Uint32(body[4:]))
								if count <= len(r.data) {
									appendChunk(files[r.key], r.offset, r.data[:count], core.FragmentTime(fragment), "client_to_server")
								}
							}
						case SMB2_CLOSE:
							if t := files[r.key]; t != nil {
								if len(body) >= 60 && binary.LittleEndian.Uint16(body[2:])&1 != 0 {
									t.size = binary.LittleEndian.Uint64(body[48:])
									t.sizeKnown = true
								} else if t.created {
									for _, chunk := range t.chunks {
										t.size = max(t.size, chunk.offset+uint64(len(chunk.data)))
									}
									t.sizeKnown = true
								}
								publish(r.key)
							}
						}
					}
				}
			advance:
				if next == 0 {
					break
				}
				message = message[next:]
			}
			buffers[side] = buffers[side][4+n:]
		}
	}
}

func decodeSMBFiles(c *core.ConversationInfo) {
	if !file.IsProtocolEnabled("SMB") || file.Decoder.Writer == nil {
		return
	}
	extractSMBFiles(c, func(t *smbTransfer, data []byte) {
		copy := *c
		copy.FirstClientPacket = time.Unix(0, t.at)
		metadata := file.FileMetadata{Filename: path.Base(strings.ReplaceAll(t.name, "\\", "/")), SMBShare: t.share, SMBPath: t.name, Host: c.ServerIP, FlowDirection: t.direction, Timestamp: t.at}
		if err := (&SMBFileExtractor{}).ExtractFile(&copy, data, metadata); err != nil {
			smbLog.Error("SMB file extraction failed")
		}
	})
}
