package dcerpc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket"
)

// DecodeSMBPipes extracts plaintext SAMR/LSA named-pipe transports independently
// of the SMB metadata writer. Encrypted SMB transforms are never inspected.
func DecodeSMBPipes(c *core.ConversationInfo) {
	if Decoder.Writer == nil {
		return
	}
	for _, pipe := range smbPipeConversations(c) {
		(&dcerpcReader{conversation: pipe}).Decode()
	}
}

func smbPipeConversations(c *core.ConversationInfo) []*core.ConversationInfo {
	type side struct {
		data    []byte
		at      int64
		stopped bool
		seen    bool
	}
	var sides [2]side
	creates := map[string]string{}
	reads := map[string]string{}
	pipes := map[string]*core.ConversationInfo{}
	var order []*core.ConversationInfo
	total := 0
	initialLoss := false
	for _, f := range c.Data {
		index := 0
		if f.Direction() == reassembly.TCPDirServerToClient {
			index = 1
		}
		s := &sides[index]
		if d, ok := f.(*core.StreamData); ok && d.SkippedBytes != 0 {
			if d.SkippedBytes == -1 && !s.seen && len(s.data) == 0 {
				initialLoss = true
			} else {
				return retainedPipes(order)
			}
		}
		if len(f.Raw()) > 0 {
			s.seen = true
		}
		if s.stopped {
			continue
		}
		if len(s.data) == 0 {
			s.at = core.FragmentTime(f)
		}
		if len(s.data)+len(f.Raw()) > 2<<20 {
			return retainedPipes(order)
		}
		s.data = append(s.data, f.Raw()...)
		for len(s.data) >= 4 {
			n := int(s.data[1])<<16 | int(s.data[2])<<8 | int(s.data[3])
			if s.data[0] != 0 || n > 1<<20 {
				s.stopped = true
				s.data = nil
				break
			}
			if len(s.data) < 4+n {
				break
			}
			message := s.data[4 : 4+n]
			for len(message) >= 64 && bytes.Equal(message[:4], []byte{0xfe, 'S', 'M', 'B'}) {
				if binary.LittleEndian.Uint16(message[4:]) != 64 {
					break
				}
				next := int(binary.LittleEndian.Uint32(message[20:]))
				frame := message
				if next != 0 {
					if next < 64 || next > len(message) {
						break
					}
					frame = message[:next]
				}
				body := frame[64:]
				command := binary.LittleEndian.Uint16(frame[12:])
				response := binary.LittleEndian.Uint32(frame[16:])&1 != 0
				status := binary.LittleEndian.Uint32(frame[8:])
				scope := fmt.Sprintf("%x:%x", frame[40:48], frame[36:40])
				mid := fmt.Sprintf("%x:%x", frame[40:48], frame[24:32])
				key := ""
				var payload []byte
				slice := func(offset, length uint32) []byte {
					if offset < 64 || offset > uint32(len(frame)) || length > uint32(len(frame))-offset {
						return nil
					}
					return frame[offset : offset+length]
				}
				switch command {
				case 5:
					if !response && len(body) >= 48 && len(creates) < 1024 {
						name := slice(uint32(binary.LittleEndian.Uint16(body[44:])), uint32(binary.LittleEndian.Uint16(body[46:])))
						if len(name)%2 == 0 {
							u := make([]uint16, len(name)/2)
							for i := range u {
								u[i] = binary.LittleEndian.Uint16(name[i*2:])
							}
							p := strings.Trim(strings.ToLower(string(utf16.Decode(u))), "\\")
							p = strings.TrimPrefix(p, "pipe\\")
							if p == "samr" || p == "lsarpc" {
								creates[mid] = p
							}
						}
					} else if response && len(body) >= 80 && status == 0 {
						if name, ok := creates[mid]; ok && len(order) < 32 {
							key = scope + fmt.Sprintf(":%x", body[64:80])
							copy := *c
							copy.Data = nil
							copy.ClientData = nil
							copy.ServerData = nil
							copy.Ident = c.Ident + "|pipe:" + name + ":" + key
							if initialLoss {
								copy.Ident += "|initial-loss-unknown"
							}
							pipes[key] = &copy
							order = append(order, &copy)
						}
						delete(creates, mid)
						key = ""
					}
				case 8:
					if !response && len(body) >= 32 && len(reads) < 1024 {
						reads[mid] = scope + fmt.Sprintf(":%x", body[16:32])
					} else if response && len(body) >= 16 && status == 0 {
						key = reads[mid]
						delete(reads, mid)
						payload = slice(uint32(body[2]), binary.LittleEndian.Uint32(body[4:]))
					}
				case 9:
					if !response && len(body) >= 32 {
						key = scope + fmt.Sprintf(":%x", body[16:32])
						payload = slice(uint32(binary.LittleEndian.Uint16(body[2:])), binary.LittleEndian.Uint32(body[4:]))
					}
				case 11:
					if len(body) >= 40 && binary.LittleEndian.Uint32(body[4:]) == 0x11c017 && (!response || status == 0) {
						key = scope + fmt.Sprintf(":%x", body[8:24])
						at := 24
						if response {
							at = 32
						}
						payload = slice(binary.LittleEndian.Uint32(body[at:]), binary.LittleEndian.Uint32(body[at+4:]))
					}
				case 6:
					if !response && len(body) >= 24 {
						key = scope + fmt.Sprintf(":%x", body[8:24])
						delete(pipes, key)
						key = ""
					}
				}
				if pipe := pipes[key]; pipe != nil && len(payload) > 0 {
					total += len(payload)
					if total > 8<<20 {
						return retainedPipes(order)
					}
					pipe.Data = append(pipe.Data, &core.StreamData{RawData: append([]byte(nil), payload...), Dir: f.Direction(), CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, s.at)}})
				}
				if next == 0 {
					break
				}
				message = message[next:]
			}
			s.data = s.data[4+n:]
			s.at = core.FragmentTime(f)
		}
	}
	return retainedPipes(order)
}

func retainedPipes(order []*core.ConversationInfo) []*core.ConversationInfo {
	var result []*core.ConversationInfo
	for _, pipe := range order {
		if len(pipe.Data) > 0 {
			result = append(result, pipe)
		}
	}
	return result
}
