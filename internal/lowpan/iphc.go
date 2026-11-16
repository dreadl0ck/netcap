package lowpan

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

type Options struct {
	Source, Destination       uint16
	Contexts                  map[uint8]netip.Prefix
	IntegrityVerified         bool
	sourceIID, destinationIID *[8]byte
}

type Result struct {
	Packet      []byte
	Synthesized []string
	ContextIDs  []uint8
}
type cursor struct {
	data   []byte
	offset int
	err    error
}

func (c *cursor) take(n int) []byte {
	if c.err != nil {
		return make([]byte, n)
	}
	if n < 0 || n > len(c.data)-c.offset {
		c.err = fmt.Errorf("truncated IPHC field")
		return make([]byte, max(0, n))
	}
	b := c.data[c.offset : c.offset+n]
	c.offset += n
	return b
}
func (c *cursor) byte() byte { return c.take(1)[0] }

func Decode(data []byte, options Options) (Result, error) { return decode(data, options, 0) }

func decode(data []byte, o Options, depth int) (Result, error) {
	if len(data) < 2 || len(data) > 65535 || depth > 8 || data[0]&0xe0 != 0x60 {
		return Result{}, fmt.Errorf("invalid IPHC dispatch/length/depth")
	}
	c := &cursor{data: data}
	first, second := c.byte(), c.byte()
	sci, dci := uint8(0), uint8(0)
	if second&0x80 != 0 {
		ids := c.byte()
		sci, dci = ids>>4, ids&15
	}
	var tc byte
	var flow uint32
	switch first >> 3 & 3 {
	case 0:
		x := c.take(4)
		tc = x[0]<<2 | x[0]>>6
		flow = uint32(x[1]&15)<<16 | uint32(x[2])<<8 | uint32(x[3])
	case 1:
		x := c.take(3)
		tc = x[0] >> 6
		flow = uint32(x[0]&15)<<16 | uint32(x[1])<<8 | uint32(x[2])
	case 2:
		x := c.byte()
		tc = x<<2 | x>>6
	}
	next := byte(0)
	compressed := first&4 != 0
	if !compressed {
		next = c.byte()
	}
	hop := []byte{0, 1, 64, 255}[first&3]
	if first&3 == 0 {
		hop = c.byte()
	}
	src, err := address(c, second>>4&3, second&0x40 != 0, sci, o.Source, o.sourceIID, o.Contexts, true)
	if err != nil {
		return Result{}, err
	}
	var dst [16]byte
	if second&8 != 0 {
		dst, err = multicast(c, second&3, second&4 != 0, dci, o.Contexts)
	} else {
		dst, err = address(c, second&3, second&4 != 0, dci, o.Destination, o.destinationIID, o.Contexts, false)
	}
	if err != nil {
		return Result{}, err
	}
	if c.err != nil {
		return Result{}, c.err
	}
	synth := []string{"IPv6-IPHC-header-restored"}
	var ids []uint8
	if second&0x40 != 0 && second>>4&3 != 0 {
		ids = append(ids, sci)
	}
	if second&4 != 0 {
		if len(ids) == 0 || ids[0] != dci {
			ids = append(ids, dci)
		}
	}
	var payload []byte
	if compressed {
		next, payload, err = nhc(c, o, src, dst, depth, &synth, &ids)
	} else {
		payload = append([]byte(nil), data[c.offset:]...)
	}
	if err != nil {
		return Result{}, err
	}
	if c.err != nil {
		return Result{}, c.err
	}
	if len(payload) > 65535 {
		return Result{}, fmt.Errorf("IPHC expanded payload exceeds IPv6 length")
	}
	out := make([]byte, 40+len(payload))
	binary.BigEndian.PutUint32(out, 0x60000000|uint32(tc)<<20|flow)
	binary.BigEndian.PutUint16(out[4:], uint16(len(payload)))
	out[6], out[7] = next, hop
	copy(out[8:], src[:])
	copy(out[24:], dst[:])
	copy(out[40:], payload)
	return Result{Packet: out, Synthesized: synth, ContextIDs: ids}, nil
}

func address(c *cursor, mode byte, stateful bool, id uint8, mac uint16, override *[8]byte, contexts map[uint8]netip.Prefix, source bool) ([16]byte, error) {
	var out [16]byte
	if stateful && mode == 0 {
		if source {
			return out, nil
		}
		return out, fmt.Errorf("reserved IPHC destination mode")
	}
	if !stateful && mode == 0 {
		copy(out[:], c.take(16))
		return out, nil
	}
	if !stateful {
		out[0], out[1] = 0xfe, 0x80
	}
	switch mode {
	case 1:
		copy(out[8:], c.take(8))
	case 2:
		copy(out[8:], []byte{0, 0, 0, 0xff, 0xfe, 0})
		copy(out[14:], c.take(2))
	case 3:
		if override != nil {
			copy(out[8:], override[:])
		} else {
			copy(out[8:], []byte{0, 0, 0, 0xff, 0xfe, 0, byte(mac >> 8), byte(mac)})
		}
	}
	if stateful {
		prefix, ok := contexts[id]
		if !ok || !prefix.IsValid() || !prefix.Addr().Is6() {
			return out, fmt.Errorf("unknown IPHC context %d", id)
		}
		bits := prefix.Bits()
		raw := prefix.Masked().Addr().As16()
		for i := 0; i < bits; i++ {
			mask := byte(1 << (7 - i%8))
			out[i/8] = (out[i/8] &^ mask) | (raw[i/8] & mask)
		}
	}
	return out, nil
}

func multicast(c *cursor, mode byte, stateful bool, id uint8, contexts map[uint8]netip.Prefix) ([16]byte, error) {
	var out [16]byte
	out[0] = 0xff
	if stateful {
		prefix, ok := contexts[id]
		if mode != 0 || !ok || !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Bits() > 64 {
			return out, fmt.Errorf("invalid or unknown IPHC multicast context %d", id)
		}
		x := c.take(6)
		out[1], out[2], out[3] = x[0], x[1], byte(prefix.Bits())
		raw := prefix.Masked().Addr().As16()
		copy(out[4:12], raw[:8])
		copy(out[12:], x[2:])
		return out, nil
	}
	switch mode {
	case 0:
		copy(out[:], c.take(16))
	case 1:
		x := c.take(6)
		out[1] = x[0]
		copy(out[11:], x[1:])
	case 2:
		x := c.take(4)
		out[1] = x[0]
		copy(out[13:], x[1:])
	case 3:
		out[1] = 2
		out[15] = c.byte()
	}
	return out, nil
}

func nhc(c *cursor, o Options, src, dst [16]byte, depth int, synth *[]string, ids *[]uint8) (byte, []byte, error) {
	if depth > 8 {
		return 0, nil, fmt.Errorf("IPHC next-header depth exceeded")
	}
	kind := c.byte()
	if kind&0xf8 == 0xf0 {
		var source, destination uint16
		switch kind & 3 {
		case 0:
			source = binary.BigEndian.Uint16(c.take(2))
			destination = binary.BigEndian.Uint16(c.take(2))
		case 1:
			source = binary.BigEndian.Uint16(c.take(2))
			destination = 0xf000 | uint16(c.byte())
		case 2:
			source = 0xf000 | uint16(c.byte())
			destination = binary.BigEndian.Uint16(c.take(2))
		case 3:
			ports := c.byte()
			source = 0xf0b0 | uint16(ports>>4)
			destination = 0xf0b0 | uint16(ports&15)
		}
		checksum := uint16(0)
		if kind&4 == 0 {
			checksum = binary.BigEndian.Uint16(c.take(2))
			if checksum == 0 {
				return 0, nil, fmt.Errorf("invalid zero IPv6 UDP checksum")
			}
		} else if !o.IntegrityVerified {
			return 0, nil, fmt.Errorf("elided UDP checksum lacks verified additional integrity")
		}
		if c.err != nil {
			return 0, nil, c.err
		}
		n := 8 + len(c.data) - c.offset
		if n > 65535 {
			return 0, nil, fmt.Errorf("IPHC UDP length exceeded")
		}
		udp := make([]byte, n)
		binary.BigEndian.PutUint16(udp, source)
		binary.BigEndian.PutUint16(udp[2:], destination)
		binary.BigEndian.PutUint16(udp[4:], uint16(n))
		binary.BigEndian.PutUint16(udp[6:], checksum)
		copy(udp[8:], c.data[c.offset:])
		c.offset = len(c.data)
		if kind&4 != 0 {
			sum := Checksum(src, dst, 17, udp)
			if sum == 0 {
				sum = 0xffff
			}
			binary.BigEndian.PutUint16(udp[6:], sum)
			*synth = append(*synth, "UDP-checksum-restored-after-integrity-verification")
		}
		*synth = append(*synth, "UDP-NHC-header-restored")
		return 17, udp, nil
	}
	if kind&0xf0 != 0xe0 {
		return 0, nil, fmt.Errorf("unsupported IPHC NHC 0x%02x", kind)
	}
	eid := kind >> 1 & 7
	if eid == 7 {
		if kind&1 != 0 {
			return 0, nil, fmt.Errorf("invalid nested IPv6 NHC flag")
		}
		var si, di [8]byte
		copy(si[:], src[8:])
		copy(di[:], dst[8:])
		o.sourceIID, o.destinationIID = &si, &di
		inner, err := decode(c.data[c.offset:], o, depth+1)
		if err != nil {
			return 0, nil, err
		}
		c.offset = len(c.data)
		*synth = append(*synth, inner.Synthesized...)
		for _, id := range inner.ContextIDs {
			found := false
			for _, known := range *ids {
				if id == known {
					found = true
				}
			}
			if !found {
				*ids = append(*ids, id)
			}
		}
		return 41, inner.Packet, nil
	}
	if eid > 4 {
		return 0, nil, fmt.Errorf("reserved IPHC extension ID")
	}
	next := byte(0)
	if kind&1 == 0 {
		next = c.byte()
	}
	length := 7
	if eid != 2 {
		length = int(c.byte())
	}
	body := append([]byte(nil), c.take(length)...)
	if c.err != nil {
		return 0, nil, c.err
	}
	if eid == 2 && kind&1 != 0 && binary.BigEndian.Uint16(body[1:3])>>3 != 0 {
		return 0, nil, fmt.Errorf("compressed next header on non-initial fragment")
	}
	if eid != 2 && (len(body)+2)%8 != 0 {
		if eid != 0 && eid != 3 {
			return 0, nil, fmt.Errorf("unaligned IPHC extension")
		}
		n := 8 - (len(body)+2)%8
		if n == 1 {
			body = append(body, 0)
		} else {
			body = append(body, 1, byte(n-2))
			body = append(body, make([]byte, n-2)...)
		}
		*synth = append(*synth, "IPv6-extension-padding-restored")
	}
	var rest []byte
	var err error
	if kind&1 != 0 {
		next, rest, err = nhc(c, o, src, dst, depth+1, synth, ids)
	} else {
		rest = append([]byte(nil), c.data[c.offset:]...)
		c.offset = len(c.data)
	}
	if err != nil {
		return 0, nil, err
	}
	header := []byte{next}
	if eid != 2 {
		header = append(header, byte((len(body)+2)/8-1))
	}
	header = append(header, body...)
	header = append(header, rest...)
	return []byte{0, 43, 44, 60, 135}[eid], header, nil
}

func Checksum(src, dst [16]byte, next byte, payload []byte) uint16 {
	var sum uint32
	add := func(data []byte) {
		for len(data) > 1 {
			sum += uint32(binary.BigEndian.Uint16(data))
			data = data[2:]
		}
		if len(data) == 1 {
			sum += uint32(data[0]) << 8
		}
	}
	add(src[:])
	add(dst[:])
	sum += uint32(len(payload)>>16) + uint32(len(payload)&65535) + uint32(next)
	add(payload)
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
