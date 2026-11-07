package gateway

import (
	"context"
	"encoding/binary"
	"io"
	"net"
)

const (
	mysqlProtocol41   uint32 = 1 << 9
	mysqlSSL          uint32 = 1 << 11
	mysqlSecure       uint32 = 1 << 15
	mysqlPlugin       uint32 = 1 << 19
	mysqlAttrs        uint32 = 1 << 20
	mysqlAuthLenenc   uint32 = 1 << 21
	mysqlDeprecateEOF uint32 = 1 << 24
	// Compression, LOCAL INFILE, multi-results, session tracking, optional
	// metadata, query attributes and MFA are deliberately not negotiated.
	mysqlCapabilities uint32 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 6) | (1 << 8) | mysqlProtocol41 | (1 << 10) | mysqlSSL | (1 << 12) | (1 << 13) | mysqlSecure | mysqlPlugin | mysqlAttrs | mysqlAuthLenenc | mysqlDeprecateEOF
)

func mysqlPacket(seq byte, p []byte) []byte {
	return append([]byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), seq}, p...)
}
func (g *Gateway) mysqlRead(ctx context.Context, c net.Conn, seq byte, idle bool) ([]byte, error) {
	var h [4]byte
	wait := g.cfg.IOTimeout
	if idle {
		wait = g.cfg.IdleTimeout
	}
	c.SetReadDeadline(deadline(ctx, wait))
	if _, err := io.ReadFull(c, h[:1]); err != nil {
		return nil, err
	}
	c.SetReadDeadline(deadline(ctx, g.cfg.IOTimeout))
	if _, err := io.ReadFull(c, h[1:]); err != nil {
		return nil, err
	}
	n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	if h[3] != seq || n == 0xffffff || n > g.cfg.MaxMessageBytes {
		return nil, errFrame
	}
	p := make([]byte, n)
	_, err := io.ReadFull(c, p)
	return p, err
}
func mysqlLenenc(b []byte) (uint64, []byte, bool) {
	if len(b) == 0 {
		return 0, nil, false
	}
	n := 0
	switch b[0] {
	case 0xfc:
		n = 2
	case 0xfd:
		n = 3
	case 0xfe:
		n = 8
	case 0xfb, 0xff:
		return 0, nil, false
	default:
		return uint64(b[0]), b[1:], true
	}
	if len(b) < n+1 {
		return 0, nil, false
	}
	var v uint64
	for i := 0; i < n; i++ {
		v |= uint64(b[i+1]) << uint(8*i)
	}
	return v, b[n+1:], true
}
func mysqlString(b []byte) ([]byte, []byte, bool) {
	n, r, ok := mysqlLenenc(b)
	if !ok || n > uint64(len(r)) {
		return nil, nil, false
	}
	return r[:int(n)], r[int(n):], true
}

// greetingOffsets requires a full protocol-10, protocol-4.1 greeting.
func mysqlGreeting(b []byte) (lo, hi, charset int, caps uint32, ok bool) {
	if len(b) < 2 || b[0] != 10 {
		return
	}
	_, r, valid := pgCString(b[1:])
	if !valid {
		return
	}
	pos := len(b) - len(r)
	lo = pos + 4 + 8 + 1
	hi = lo + 2 + 1 + 2
	charset = lo + 2
	if len(b) < hi+2+1+10 || b[pos+12] != 0 {
		return
	}
	caps = uint32(binary.LittleEndian.Uint16(b[lo:])) | uint32(binary.LittleEndian.Uint16(b[hi:]))<<16
	start := hi + 13
	if len(b) < start+13 || b[start+12] != 0 {
		return
	}
	if caps&mysqlPlugin != 0 {
		plugin, r, valid := pgCString(b[start+13:])
		if !valid || len(r) != 0 || !mysqlAuthPlugin(plugin) || b[hi+2] != 21 {
			return
		}
	} else if len(b) != start+13 {
		return
	}
	ok = caps&mysqlProtocol41 != 0 && caps&mysqlSecure != 0
	return
}

func mysqlAuthPlugin(name string) bool {
	return name == "mysql_native_password" || name == "caching_sha2_password" || name == "sha256_password"
}
func mysqlSetCaps(b []byte, lo, hi int, caps uint32) {
	binary.LittleEndian.PutUint16(b[lo:], uint16(caps))
	binary.LittleEndian.PutUint16(b[hi:], uint16(caps>>16))
}

func mysqlLogin(b []byte) (user, database string, caps uint32, ok bool) {
	if len(b) < 33 {
		return
	}
	caps = binary.LittleEndian.Uint32(b)
	if caps&mysqlProtocol41 == 0 || caps&mysqlSecure == 0 {
		return
	}
	var r []byte
	user, r, ok = pgCString(b[32:])
	if !ok || len(user) > 256 {
		return "", "", 0, false
	}
	if caps&mysqlAuthLenenc != 0 {
		_, r, ok = mysqlString(r)
	} else {
		if len(r) < 1 || int(r[0]) > len(r)-1 {
			return "", "", 0, false
		}
		r = r[int(r[0])+1:]
		ok = true
	}
	if !ok {
		return "", "", 0, false
	}
	if caps&(1<<3) != 0 {
		database, r, ok = pgCString(r)
		if !ok || len(database) > 256 {
			return "", "", 0, false
		}
	}
	if caps&mysqlPlugin != 0 {
		var plugin string
		plugin, r, ok = pgCString(r)
		if !ok || !mysqlAuthPlugin(plugin) {
			return "", "", 0, false
		}
	}
	if caps&mysqlAttrs != 0 {
		var attrs []byte
		attrs, r, ok = mysqlString(r)
		if !ok {
			return "", "", 0, false
		}
		for len(attrs) > 0 {
			_, attrs, ok = mysqlString(attrs)
			if !ok {
				return "", "", 0, false
			}
			_, attrs, ok = mysqlString(attrs)
			if !ok {
				return "", "", 0, false
			}
		}
	}
	return user, database, caps, len(r) == 0
}
func mysqlError(seq byte) []byte {
	return mysqlPacket(seq, append([]byte{0xff, 0x76, 0x04, '#', '4', '2', '0', '0', '0'}, []byte("blocked or unsupported by gateway")...))
}
func mysqlStatus(b []byte, deprecate bool) (uint16, bool) {
	if len(b) == 0 {
		return 0, false
	}
	if b[0] == 0xfe && !deprecate {
		if len(b) != 5 {
			return 0, false
		}
		return binary.LittleEndian.Uint16(b[3:]), true
	}
	if b[0] != 0x00 && b[0] != 0xfe {
		return 0, false
	}
	_, r, ok := mysqlLenenc(b[1:])
	if !ok {
		return 0, false
	}
	_, r, ok = mysqlLenenc(r)
	if !ok || len(r) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint16(r), true
}
func mysqlTerminal(b []byte, deprecate bool) bool {
	status, ok := mysqlStatus(b, deprecate)
	return ok && status&(0x8|0x40) == 0
}

type mysqlConversation struct {
	g              *Gateway
	ctx            context.Context
	c              net.Conn
	seq            byte
	bytes, packets int
	wire           []byte
}

func (s *mysqlConversation) read() ([]byte, error) {
	if s.packets >= s.g.cfg.MaxSessionMessages {
		return nil, errFrame
	}
	b, err := s.g.mysqlRead(s.ctx, s.c, s.seq, false)
	if err != nil || len(b) == 0 {
		return nil, errFrame
	}
	s.seq++
	s.bytes += len(b) + 4
	s.packets++
	if s.bytes > s.g.cfg.MaxMessageBytes {
		return nil, errFrame
	}
	s.wire = append(s.wire, mysqlPacket(s.seq-1, b)...)
	return b, nil
}
func mysqlColumn(b []byte) bool {
	for i := 0; i < 6; i++ {
		_, r, ok := mysqlString(b)
		if !ok {
			return false
		}
		b = r
	}
	n, r, ok := mysqlLenenc(b)
	return ok && n == 12 && len(r) == 12
}
func mysqlTextRow(b []byte, columns int) bool {
	for i := 0; i < columns; i++ {
		if len(b) > 0 && b[0] == 0xfb {
			b = b[1:]
			continue
		}
		_, r, ok := mysqlString(b)
		if !ok {
			return false
		}
		b = r
	}
	return len(b) == 0
}

func (s *mysqlConversation) result(deprecate, binaryRows bool) (bool, error) {
	b, err := s.read()
	if err != nil {
		return false, err
	}
	if b[0] == 0xff {
		return false, nil
	}
	if b[0] == 0x00 {
		if !mysqlTerminal(b, true) {
			return false, errFrame
		}
		return true, nil
	}
	if b[0] == 0xfb {
		return false, errFrame
	} // Never forward a file request to a client.
	count, r, ok := mysqlLenenc(b)
	if !ok || len(r) != 0 || count < 1 || count > uint64(s.g.cfg.MaxStateEntries) {
		return false, errFrame
	}
	for i := uint64(0); i < count; i++ {
		b, err = s.read()
		if err != nil {
			return false, err
		}
		if b[0] == 0xff {
			return false, nil
		}
		if !mysqlColumn(b) {
			return false, errFrame
		}
	}
	if !deprecate {
		b, err = s.read()
		if err != nil || b[0] != 0xfe || !mysqlTerminal(b, false) {
			return false, errFrame
		}
	}
	for {
		b, err = s.read()
		if err != nil {
			return false, err
		}
		if b[0] == 0xff {
			return false, nil
		}
		if b[0] == 0xfe && len(b) < 9 {
			if !mysqlTerminal(b, deprecate) {
				return false, errFrame
			}
			return true, nil
		}
		if binaryRows {
			if b[0] != 0 || len(b) < 1+(int(count)+9)/8 {
				return false, errFrame
			}
		} else if !mysqlTextRow(b, int(count)) {
			return false, errFrame
		}
	}
}
