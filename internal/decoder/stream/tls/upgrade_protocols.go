package tls

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"io"
	"net/http"
	"strings"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

const maxUpgradeBytes = 64 * 1024

// Never join across loss, nor retain a whole application stream to find an upgrade.
func upgradePrefixes(fragments core.DataFragments) [2][]byte {
	var data [2][]byte
	var stopped [2]bool
	for _, f := range fragments {
		side := fragmentSide(f)
		if d, ok := f.(*core.StreamData); ok && d.SkippedBytes != 0 && (d.SkippedBytes > 0 || len(data[side]) > 0) {
			stopped[side] = true
		}
		if !stopped[side] {
			n := min(len(f.Raw()), maxUpgradeBytes-len(data[side]))
			data[side] = append(data[side], f.Raw()[:n]...)
		}
	}
	return data
}

type upgradeParser func(client, server []byte) ([2]int, bool)

func tryUpgrade(data [2][]byte, parse upgradeParser) ([2]int, bool) {
	if b, ok := parse(data[0], data[1]); ok {
		return b, true
	}
	b, ok := parse(data[1], data[0])
	return [2]int{b[1], b[0]}, ok
}

func negotiatedUpgrade(fragments core.DataFragments, primary string) ([2]int, bool) {
	data := upgradePrefixes(fragments)
	// HTTP bodies are not candidates for another protocol's upgrade grammar.
	if primary == "HTTP" {
		return tryUpgrade(data, connectBounds)
	}
	for _, parse := range []upgradeParser{connectBounds, ldapBounds, postgresBounds, mysqlBounds, xmppBounds, ircBounds, rdpBounds, socksBounds} {
		if bounds, ok := tryUpgrade(data, parse); ok {
			return bounds, true
		}
	}
	switch primary {
	case "SMTP", "POP3", "IMAP", "FTP", "":
		return cleartextUpgrade(fragments)
	}
	return [2]int{}, false
}

func connectBounds(client, server []byte) ([2]int, bool) {
	cr, sr := bytes.NewReader(client), bytes.NewReader(server)
	c, s := bufio.NewReader(cr), bufio.NewReader(sr)
	drain := func(body io.ReadCloser) bool {
		defer body.Close()
		n, err := io.Copy(io.Discard, io.LimitReader(body, maxUpgradeBytes+1))
		return err == nil && n <= maxUpgradeBytes
	}
	for range 32 {
		req, err := http.ReadRequest(c)
		if err != nil || !drain(req.Body) {
			return [2]int{}, false
		}
		requestEnd := len(client) - cr.Len() - c.Buffered()
		for range 16 {
			resp, err := http.ReadResponse(s, req)
			if err != nil {
				return [2]int{}, false
			}
			if req.Method == "CONNECT" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return [2]int{requestEnd, len(server) - sr.Len() - s.Buffered()}, true
			}
			if !drain(resp.Body) {
				return [2]int{}, false
			}
			if resp.StatusCode >= 200 || resp.StatusCode == 101 {
				break
			}
		}
	}
	return [2]int{}, false
}

// Definite-length BER only; no recursive allocation or indefinite-length search.
func berField(b []byte) (tag byte, value, rest []byte, ok bool) {
	if len(b) < 2 {
		return
	}
	tag, n, h := b[0], int(b[1]), 2
	if n&128 != 0 {
		count := n & 127
		if count == 0 || count > 3 || len(b) < 2+count {
			return 0, nil, nil, false
		}
		n, h = 0, 2+count
		for _, v := range b[2:h] {
			n = n<<8 | int(v)
		}
	}
	if n > maxUpgradeBytes || n > len(b)-h {
		return 0, nil, nil, false
	}
	return tag, b[h : h+n], b[h+n:], true
}

const ldapStartTLSOID = "1.3.6.1.4.1.1466.20037"

func ldapMessage(b []byte) (id string, op byte, value, rest []byte, ok bool) {
	tag, seq, rest, ok := berField(b)
	if !ok || tag != 0x30 {
		return "", 0, nil, nil, false
	}
	tag, ident, seq, ok := berField(seq)
	if !ok || tag != 2 || len(ident) == 0 || len(ident) > 4 || ident[0]&128 != 0 {
		return "", 0, nil, nil, false
	}
	op, value, extra, ok := berField(seq)
	if len(extra) > 0 {
		t, _, tail, valid := berField(extra)
		ok = ok && valid && t == 0xa0 && len(tail) == 0
	}
	return string(bytes.TrimLeft(ident, "\x00")), op, value, rest, ok
}

func ldapBounds(client, server []byte) ([2]int, bool) {
	c := client
	for len(c) > 0 {
		id, op, value, rest, ok := ldapMessage(c)
		if !ok {
			return [2]int{}, false
		}
		c = rest
		if op != 0x77 {
			continue
		}
		tag, oid, extra, ok := berField(value)
		if !ok || id == "" || tag != 0x80 || string(oid) != ldapStartTLSOID || len(extra) != 0 {
			continue
		}
		s := server
		for len(s) > 0 {
			rid, rop, result, tail, valid := ldapMessage(s)
			if !valid {
				return [2]int{}, false
			}
			s = tail
			if rid != id {
				continue
			}
			t, code, result, valid := berField(result)
			if !valid || rop != 0x78 || t != 0x0a || !bytes.Equal(code, []byte{0}) {
				return [2]int{}, false
			}
			for range 2 { // matchedDN and diagnosticMessage
				t, _, result, valid = berField(result)
				if !valid || t != 4 {
					return [2]int{}, false
				}
			}
			for len(result) > 0 {
				var v []byte
				t, v, result, valid = berField(result)
				if !valid || t != 0x8a || string(v) != ldapStartTLSOID {
					return [2]int{}, false
				}
			}
			return [2]int{len(client) - len(c), len(server) - len(s)}, true
		}
		return [2]int{}, false
	}
	return [2]int{}, false
}

func postgresBounds(c, s []byte) ([2]int, bool) {
	// PostgreSQL may reject GSS encryption before the client requests SSL.
	ci, si := 0, 0
	if len(c) >= 8 && bytes.Equal(c[:8], []byte{0, 0, 0, 8, 4, 210, 22, 48}) {
		if len(s) == 0 || s[0] != 'N' {
			return [2]int{}, false
		}
		ci, si = 8, 1
	}
	if len(c) >= ci+8 && len(s) > si && bytes.Equal(c[ci:ci+8], []byte{0, 0, 0, 8, 4, 210, 22, 47}) && s[si] == 'S' {
		return [2]int{ci + 8, si + 1}, true
	}
	return [2]int{}, false
}

func mysqlPacket(b []byte, sequence byte) ([]byte, int, bool) {
	if len(b) < 4 || b[3] != sequence {
		return nil, 0, false
	}
	n := int(b[0]) | int(b[1])<<8 | int(b[2])<<16
	if n > maxUpgradeBytes-4 || len(b) < n+4 {
		return nil, 0, false
	}
	return b[4 : n+4], n + 4, true
}

func mysqlBounds(c, s []byte) ([2]int, bool) {
	greeting, sn, ok := mysqlPacket(s, 0)
	if !ok || len(greeting) < 1 || greeting[0] != 10 {
		return [2]int{}, false
	}
	end := bytes.IndexByte(greeting[1:], 0) + 1
	// protocol, NUL-terminated version, connection id, salt, filler, capabilities
	if end <= 1 || len(greeting) < end+32 || greeting[end+13] != 0 || !bytes.Equal(greeting[end+22:end+32], make([]byte, 10)) {
		return [2]int{}, false
	}
	serverCaps := binary.LittleEndian.Uint16(greeting[end+14 : end+16])
	request, cn, ok := mysqlPacket(c, 1)
	if !ok || len(request) != 32 || serverCaps&0xa00 != 0xa00 || binary.LittleEndian.Uint32(request[:4])&0xa00 != 0xa00 || !bytes.Equal(request[9:], make([]byte, 23)) {
		return [2]int{}, false
	}
	return [2]int{cn, sn}, true
}

func xmppCommand(b []byte, name string) (int, bool) {
	d := xml.NewDecoder(bytes.NewReader(b))
	depth, stream, command := 0, false, false
	for {
		tok, err := d.Token()
		if err != nil || d.InputOffset() > maxUpgradeBytes {
			return 0, false
		}
		switch v := tok.(type) {
		case xml.StartElement:
			depth++
			if depth > 32 {
				return 0, false
			}
			if depth == 1 && v.Name.Space == "http://etherx.jabber.org/streams" && v.Name.Local == "stream" {
				stream = true
			}
			if depth == 1 && !stream && (v.Name.Space != "urn:ietf:params:xml:ns:xmpp-tls" || v.Name.Local != name) {
				return 0, false
			}
			if depth == 1 || stream && depth == 2 {
				if v.Name.Space == "urn:ietf:params:xml:ns:xmpp-tls" {
					if v.Name.Local != name || len(v.Attr) > 1 {
						return 0, false
					}
					command = true
				}
			} else if command {
				return 0, false
			}
		case xml.EndElement:
			if command {
				return int(d.InputOffset()), true
			}
			depth--
		case xml.CharData:
			if (command || depth == 0) && len(bytes.TrimSpace(v)) != 0 {
				return 0, false
			}
		case xml.Directive:
			return 0, false
		}
	}
}

func xmppBounds(c, s []byte) ([2]int, bool) {
	cn, ok := xmppCommand(c, "starttls")
	sn, ready := xmppCommand(s, "proceed")
	return [2]int{cn, sn}, ok && ready
}

func ircBounds(c, s []byte) ([2]int, bool) {
	var bounds [2]int
	for side, data := range [][]byte{c, s} {
		for len(data) > 0 {
			end := bytes.IndexByte(data, '\n')
			if end < 0 || end > 8192 {
				return [2]int{}, false
			}
			line := strings.TrimSuffix(string(data[:end]), "\r")
			data = data[end+1:]
			bounds[side] += end + 1
			fields := strings.Fields(line)
			if len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
				fields = fields[1:]
			}
			if len(fields) > 0 && strings.HasPrefix(fields[0], ":") {
				fields = fields[1:]
			}
			if len(fields) == 0 {
				return [2]int{}, false
			}
			cmd := strings.ToUpper(fields[0])
			if side == 0 && cmd != "CAP" && cmd != "NICK" && cmd != "USER" && cmd != "PASS" && cmd != "PING" && cmd != "PONG" && cmd != "STARTTLS" {
				return [2]int{}, false
			}
			numeric := len(cmd) == 3 && cmd[0] >= '0' && cmd[0] <= '9' && cmd[1] >= '0' && cmd[1] <= '9' && cmd[2] >= '0' && cmd[2] <= '9'
			if side == 1 && !numeric && cmd != "CAP" && cmd != "NOTICE" && cmd != "PING" && cmd != "PONG" {
				return [2]int{}, false
			}
			if side == 0 && len(fields) == 1 && strings.EqualFold(fields[0], "STARTTLS") {
				break
			}
			if side == 1 && len(fields) >= 2 && fields[0] == "670" {
				return bounds, true
			}
			if side == 1 && len(fields) > 0 && fields[0] == "691" {
				return [2]int{}, false
			}
			if len(data) == 0 {
				return [2]int{}, false
			}
		}
		if bounds[side] == 0 {
			return [2]int{}, false
		}
	}
	return [2]int{}, false
}

func rdpNegotiation(b []byte, response bool) (int, uint32, bool) {
	if len(b) < 19 || b[0] != 3 || b[1] != 0 {
		return 0, 0, false
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	code, typ := byte(0xe0), byte(1)
	if response {
		code, typ = 0xd0, 2
	}
	if n < 19 || n > 260 || len(b) < n || int(b[4])+5 != n || b[5] != code || b[10] != 0 {
		return 0, 0, false
	}
	p := b[11:n]
	if !response && (bytes.HasPrefix(p, []byte("Cookie: ")) || bytes.HasPrefix(p, []byte("RoutingToken: "))) {
		end := bytes.Index(p, []byte("\r\n"))
		if end < 0 {
			return 0, 0, false
		}
		p = p[end+2:]
	}
	if len(p) < 8 || p[0] != typ || binary.LittleEndian.Uint16(p[2:4]) != 8 {
		return 0, 0, false
	}
	if len(p) != 8 {
		// Optional RDP correlation info follows the request, never precedes it.
		if response || p[1]&8 == 0 || len(p) != 44 || p[8] != 6 || p[9] != 0 || binary.LittleEndian.Uint16(p[10:12]) != 36 {
			return 0, 0, false
		}
	}
	return n, binary.LittleEndian.Uint32(p[4:8]), true
}

func rdpBounds(c, s []byte) ([2]int, bool) {
	cn, offered, ok := rdpNegotiation(c, false)
	sn, selected, ready := rdpNegotiation(s, true)
	// Every enhanced-security selection begins with TLS; standard RDP (0) does not.
	return [2]int{cn, sn}, ok && ready && (selected == 1 || selected == 2 || selected == 4 || selected == 8 || selected == 16) && offered&selected == selected
}

func socksBounds(c, s []byte) ([2]int, bool) {
	ci, si := 0, 0
	// A capture may start at CONNECT, but never at an arbitrary embedded signature.
	if len(c) >= 3 && c[0] == 5 && c[1] > 0 && len(c) >= 2+int(c[1]) && len(s) >= 2 && s[0] == 5 && (s[1] == 0 || s[1] == 2) {
		methods := c[2 : 2+int(c[1])]
		if bytes.Contains(methods, []byte{s[1]}) && socksMessageLength(s) == 0 {
			ci, si = 2+int(c[1]), 2
			if s[1] == 2 {
				if len(c) < ci+2 || c[ci] != 1 || c[ci+1] == 0 {
					return [2]int{}, false
				}
				ci += 2 + int(c[ci+1])
				if len(c) <= ci || c[ci] == 0 {
					return [2]int{}, false
				}
				ci += 1 + int(c[ci])
				if len(c) < ci || len(s) < si+2 || s[si] != 1 || s[si+1] != 0 {
					return [2]int{}, false
				}
				si += 2
			}
		}
	}
	cn, sn := socksMessageLength(c[ci:]), socksMessageLength(s[si:])
	return [2]int{ci + cn, si + sn}, cn > 0 && sn > 0 && c[ci+1] == 1 && s[si+1] == 0
}
