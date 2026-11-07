package sipaudit

import (
	"bytes"
	"errors"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket/layers"
)

const MaxHeader = 32 << 10
const MaxBody = 256 << 10

var ErrIncomplete = errors.New("incomplete SIP message")
var ErrMalformed = errors.New("malformed SIP message")

var compact = map[string]string{
	"i": "call-id", "m": "contact", "e": "content-encoding", "l": "content-length",
	"c": "content-type", "f": "from", "s": "subject", "k": "supported", "t": "to", "v": "via",
	"a": "accept-contact", "u": "allow-events", "o": "event", "r": "refer-to", "b": "referred-by",
}

// Parse frames one message. TCP requires Content-Length; a UDP datagram without
// it owns the remaining bytes. Conflicting/duplicate lengths are never guessed.
func Parse(data []byte, tcp bool) (*layers.SIP, int, error) {
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end < 0 {
		if len(data) > MaxHeader {
			return nil, 0, ErrMalformed
		}
		return nil, 0, ErrIncomplete
	}
	if end > MaxHeader {
		return nil, 0, ErrMalformed
	}
	lines := strings.Split(string(data[:end]), "\r\n")
	s := layers.NewSIP()
	if s.ParseFirstLine([]byte(lines[0])) != nil || (s.IsResponse && (s.ResponseCode < 100 || s.ResponseCode > 699)) {
		return nil, 0, ErrMalformed
	}
	last := ""
	for _, line := range lines[1:] {
		if line == "" {
			return nil, 0, ErrMalformed
		}
		if line[0] == ' ' || line[0] == '\t' {
			if last == "" {
				return nil, 0, ErrMalformed
			}
			v := s.Headers[last]
			v[len(v)-1] += " " + strings.TrimSpace(line)
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || key == "" || strings.ContainsAny(key, " \t\x00") {
			return nil, 0, ErrMalformed
		}
		if full, ok := compact[key]; ok {
			key = full
		}
		s.Headers[key] = append(s.Headers[key], strings.TrimSpace(value))
		last = key
	}
	n := len(data) - end - 4
	lengths := s.Headers["content-length"]
	if len(lengths) > 1 || (tcp && len(lengths) == 0) {
		return nil, 0, ErrMalformed
	}
	if len(lengths) == 1 {
		value := lengths[0]
		if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return nil, 0, ErrMalformed
		}
		u, err := strconv.ParseUint(value, 10, 32)
		if err != nil || u > MaxBody {
			return nil, 0, ErrMalformed
		}
		n = int(u)
	}
	if n > MaxBody {
		return nil, 0, ErrMalformed
	}
	total := end + 4 + n
	if len(data) < total {
		return nil, 0, ErrIncomplete
	}
	if len(s.Headers["cseq"]) > 1 {
		return nil, 0, ErrMalformed
	}
	if cseq := s.Headers["cseq"]; len(cseq) == 1 {
		parts := strings.Fields(cseq[0])
		if len(parts) != 2 {
			return nil, 0, ErrMalformed
		}
		if _, err := strconv.ParseUint(parts[0], 10, 31); err != nil {
			return nil, 0, ErrMalformed
		}
		method, err := layers.GetSIPMethod(parts[1])
		if err != nil || (!s.IsResponse && method != s.Method) {
			return nil, 0, ErrMalformed
		}
		if s.IsResponse {
			s.Method = method
		}
	}
	s.BaseLayer = layers.BaseLayer{Contents: data[:end+4], Payload: data[end+4 : total]}
	return s, total, nil
}
