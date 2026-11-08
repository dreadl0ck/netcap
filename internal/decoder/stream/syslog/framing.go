package syslog

import (
	"bytes"
	"strconv"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

const maxSyslogMessage = 64 << 10

func validPRI(data []byte) bool {
	if len(data) < 3 || data[0] != '<' {
		return false
	}
	end := bytes.IndexByte(data, '>')
	if end < 2 || end > 4 {
		return false
	}
	for _, b := range data[1:end] {
		if b < '0' || b > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(string(data[1:end]))
	return err == nil && n <= 191
}

func hasSyslogPrefix(data []byte) bool {
	if validPRI(data) {
		return true
	}
	end := bytes.IndexByte(data, ' ')
	if end < 1 || end > 5 || data[0] == '0' {
		return false
	}
	for _, b := range data[:end] {
		if b < '0' || b > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(string(data[:end]))
	return err == nil && n <= maxSyslogMessage && validPRI(data[end+1:])
}

// RFC 6587 octet counting and LF framing retain independent directional state.
// An oversized/invalid octet count stops that direction until a gap; guessing
// a new boundary inside a declared payload would invent evidence.
func (s *syslogReader) decodeMessages(emit func(*types.Syslog)) {
	var pending [2][]byte
	var times [2][]int64
	var stopped [2]bool
	for _, f := range s.conversation.Data {
		d := 0
		if core.FromServer(f) {
			d = 1
		}
		if v, ok := f.(*core.StreamData); ok && v.HasGap(len(pending[d]) > 0 || stopped[d]) {
			pending[d], times[d], stopped[d] = nil, nil, false
		}
		publish := func(raw []byte, timestamp int64, transport string) {
			msg := s.parseSyslogMessage(raw)
			if msg == nil {
				return
			}
			msg.SrcIP, msg.DstIP, msg.SrcPort, msg.DstPort = s.conversation.Endpoints(f)
			msg.Timestamp, msg.Protocol, msg.CommunityID = timestamp, transport, s.conversation.CommunityID
			emit(msg)
		}
		if s.conversation.Transport == core.UDP {
			if len(f.Raw()) <= maxSyslogMessage {
				publish(f.Raw(), core.FragmentTime(f), "UDP")
			}
			continue
		}
		for _, b := range f.Raw() {
			if stopped[d] {
				continue
			}
			pending[d] = append(pending[d], b)
			times[d] = append(times[d], core.FragmentTime(f))
			data := pending[d]
			start, end := 0, 0
			if data[0] == '<' {
				if b == '\n' {
					end = len(data)
				}
			} else {
				space := bytes.IndexByte(data, ' ')
				if space < 0 {
					if len(data) > 5 || b < '0' || b > '9' || data[0] == '0' {
						stopped[d] = true
					}
				} else {
					n, err := strconv.Atoi(string(data[:space]))
					if err != nil || n <= 0 || n > maxSyslogMessage {
						stopped[d] = true
					} else if len(data) == space+1+n {
						start, end = space+1, len(data)
					}
				}
			}
			if end > 0 {
				raw := data[start:end]
				if start == 0 {
					raw = bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\r'})
				}
				publish(raw, times[d][0], "TCP")
				pending[d], times[d] = nil, nil
			}
			if len(pending[d]) > maxSyslogMessage+6 || stopped[d] {
				stopped[d] = true
				pending[d], times[d] = nil, nil
			}
		}
	}
}
