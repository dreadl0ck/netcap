package networkfirewall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

var ErrFragment = errors.New("fragment requires explicit failure verdict; reassembly unsupported")

// ParsePacket accepts a complete L3 packet. Fragmented traffic, IPv6 jumbograms,
// ESP and unknown extension headers are deliberately not classified as TCP/UDP.
func ParsePacket(b []byte) (e PacketEvent, err error) {
	bad := errors.New("malformed or truncated IP packet")
	if len(b) < 1 {
		return e, bad
	}
	var next byte
	var off int
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return e, bad
		}
		off = int(b[0]&15) * 4
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if off < 20 || n < off || n != len(b) {
			return e, bad
		}
		if binary.BigEndian.Uint16(b[6:8])&0x8000 != 0 {
			return e, bad
		}
		if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			return e, ErrFragment
		}
		e.IPVersion = 4
		e.SrcIP = netip.AddrFrom4([4]byte(b[12:16])).String()
		e.DstIP = netip.AddrFrom4([4]byte(b[16:20])).String()
		next = b[9]
	case 6:
		if len(b) < 40 || int(binary.BigEndian.Uint16(b[4:6]))+40 != len(b) {
			return e, bad
		}
		e.IPVersion = 6
		e.SrcIP = netip.AddrFrom16([16]byte(b[8:24])).String()
		e.DstIP = netip.AddrFrom16([16]byte(b[24:40])).String()
		next = b[6]
		off = 40
		for count := 0; next == 0 || next == 43 || next == 60 || next == 51 || next == 44; count++ {
			if count >= 8 || off+2 > len(b) {
				return e, bad
			}
			if next == 44 {
				return e, ErrFragment
			}
			n := (int(b[off+1]) + 1) * 8
			if next == 51 {
				n = (int(b[off+1]) + 2) * 4
			}
			if off+n > len(b) {
				return e, bad
			}
			next = b[off]
			off += n
		}
	default:
		return e, bad
	}
	switch next {
	case 6:
		if off+20 > len(b) {
			return e, bad
		}
		h := int(b[off+12]>>4) * 4
		if h < 20 || off+h > len(b) {
			return e, bad
		}
		e.Transport = "tcp"
		e.TCPFlags = int(b[off+13]) | int(b[off+12]&1)<<8
	case 17:
		if off+8 > len(b) {
			return e, bad
		}
		n := int(binary.BigEndian.Uint16(b[off+4 : off+6]))
		if n < 8 || off+n != len(b) {
			return e, bad
		}
		e.Transport = "udp"
	case 1:
		e.Transport = "icmp"
	case 58:
		e.Transport = "icmpv6"
	default:
		e.Transport = fmt.Sprintf("ip-%d", next)
	}
	if next == 6 || next == 17 {
		e.SrcPort = int(binary.BigEndian.Uint16(b[off : off+2]))
		e.DstPort = int(binary.BigEndian.Uint16(b[off+2 : off+4]))
	}
	return e, nil
}
