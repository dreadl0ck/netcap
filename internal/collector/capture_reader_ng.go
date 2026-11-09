package collector

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/bits"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

const ngSection = 0x0a0d0d0a

type captureNGInterface struct {
	link    layers.LinkType
	snaplen uint32
	units   uint64
	offset  int64
	valid   bool
}

type scopedNgReader struct {
	keyLog func([]byte)
	*captureStream
	order         binary.ByteOrder
	interfaces    []captureNGInterface
	interfaceBase int
	buffer        []byte
}

func newBoundedNGReader(input io.Reader) (*scopedNgReader, error) {
	s, err := newCaptureStream(input)
	if err != nil {
		return nil, err
	}
	r := &scopedNgReader{captureStream: s}
	kind, body, offset, err := r.block()
	if err != nil {
		return nil, err
	}
	if kind != ngSection {
		return nil, fmt.Errorf("PCAPNG must start with a section header")
	}
	if err := r.section(body, offset); err != nil {
		return nil, err
	}
	return r, nil
}

// With mixed interfaces there is no capture-wide link type. Every packet carries
// its own type and a capture-wide (not section-local) interface ordinal.
func (r *scopedNgReader) LinkType() layers.LinkType { return layers.LinkTypeNull }

func (r *scopedNgReader) block() (uint32, []byte, int64, error) {
	offset := r.offset
	if r.failed != nil {
		return 0, nil, offset, r.failed
	}
	var h [12]byte
	if err := r.read(h[:8]); err != nil {
		if err == io.EOF && offset == r.offset {
			return 0, nil, offset, io.EOF
		}
		return 0, nil, offset, r.fail(offset, fmt.Sprintf("PCAPNG block header: %v", err), false)
	}
	prefix := 8
	if binary.BigEndian.Uint32(h[:4]) == ngSection {
		if err := r.read(h[8:12]); err != nil {
			return 0, nil, offset, r.fail(offset, "truncated PCAPNG byte order magic", false)
		}
		switch binary.BigEndian.Uint32(h[8:12]) {
		case 0x1a2b3c4d:
			r.order = binary.BigEndian
		case 0x4d3c2b1a:
			r.order = binary.LittleEndian
		default:
			return 0, nil, offset, r.fail(offset, "invalid PCAPNG byte order magic", false)
		}
		prefix = 12
	}
	if r.order == nil {
		return 0, nil, offset, r.fail(offset, "PCAPNG block before section", false)
	}
	size, kind := r.order.Uint32(h[4:8]), r.order.Uint32(h[:4])
	if size < uint32(prefix+4) || size%4 != 0 || size > maxInputBlock {
		return 0, nil, offset, r.fail(offset, fmt.Sprintf("invalid PCAPNG block length %d (cap %d)", size, maxInputBlock), false)
	}
	if cap(r.buffer) < int(size)-8 {
		r.buffer = make([]byte, int(size)-8)
	}
	body := r.buffer[:int(size)-8]
	copy(body, h[8:prefix])
	if err := r.read(body[prefix-8:]); err != nil {
		return 0, nil, offset, r.fail(offset, fmt.Sprintf("truncated PCAPNG block: %v", err), false)
	}
	if r.order.Uint32(body[len(body)-4:]) != size {
		return 0, nil, offset, r.fail(offset, "PCAPNG block trailer length mismatch", false)
	}
	return kind, body[:len(body)-4], offset, nil
}

func ngOptions(data []byte, order binary.ByteOrder, visit func(uint16, []byte) error) error {
	for len(data) > 0 {
		if len(data) < 4 {
			return fmt.Errorf("truncated PCAPNG option header")
		}
		code, size := order.Uint16(data[:2]), int(order.Uint16(data[2:4]))
		data = data[4:]
		padded := (size + 3) &^ 3
		if padded > len(data) {
			return fmt.Errorf("PCAPNG option exceeds block boundary")
		}
		if code == 0 {
			if size != 0 || len(data) != 0 {
				return fmt.Errorf("invalid PCAPNG end-of-options")
			}
			return nil
		}
		if visit != nil {
			if err := visit(code, data[:size]); err != nil {
				return err
			}
		}
		data = data[padded:]
	}
	return nil
}

func (r *scopedNgReader) section(body []byte, offset int64) error {
	if len(body) < 16 || r.order.Uint16(body[4:6]) != 1 || r.order.Uint16(body[6:8]) != 0 {
		return r.fail(offset, "unsupported or malformed PCAPNG section (require 1.0)", false)
	}
	if err := ngOptions(body[16:], r.order, nil); err != nil {
		return r.fail(offset, err.Error(), false)
	}
	r.interfaceBase += len(r.interfaces)
	r.interfaces = nil
	return nil
}

func (r *scopedNgReader) addInterface(body []byte, offset int64) error {
	if r.interfaceBase+len(r.interfaces) >= maxInputInterfaces {
		return r.fail(offset, "PCAPNG interface limit exceeded", false)
	}
	// Even an invalid IDB occupies an ID. Otherwise later packets could be
	// attributed to the next interface with an entirely different link type.
	r.interfaces = append(r.interfaces, captureNGInterface{})
	if len(body) < 8 {
		return r.fail(offset, "short PCAPNG interface descriptor", true)
	}
	intf := captureNGInterface{link: layers.LinkType(r.order.Uint16(body[:2])), snaplen: r.order.Uint32(body[4:8]), units: 1_000_000, valid: true}
	err := ngOptions(body[8:], r.order, func(code uint16, value []byte) error {
		switch code {
		case 9: // if_tsresol
			if len(value) != 1 {
				return fmt.Errorf("invalid if_tsresol length")
			}
			exp := value[0] & 0x7f
			if value[0]&0x80 != 0 {
				if exp > 63 {
					return fmt.Errorf("unsupported binary if_tsresol exponent %d", exp)
				}
				intf.units = uint64(1) << exp
			} else {
				if exp > 19 {
					return fmt.Errorf("unsupported decimal if_tsresol exponent %d", exp)
				}
				intf.units = 1
				for range exp {
					intf.units *= 10
				}
			}
		case 14: // if_tsoffset is signed seconds
			if len(value) != 8 {
				return fmt.Errorf("invalid if_tsoffset length")
			}
			intf.offset = int64(r.order.Uint64(value))
		}
		return nil
	})
	if err != nil {
		return r.fail(offset, err.Error(), true)
	}
	r.interfaces[len(r.interfaces)-1] = intf
	return nil
}

func (r *scopedNgReader) packet(kind uint32, body []byte, offset int64) ([]byte, gopacket.CaptureInfo, error) {
	var ci gopacket.CaptureInfo
	bad := func(reason string) ([]byte, gopacket.CaptureInfo, error) {
		return nil, ci, r.fail(offset, reason, true)
	}
	var iface, caplen, wire uint32
	var stamp uint64
	header := 20
	if kind == 3 {
		header = 4
	}
	if len(body) < header {
		return bad("short PCAPNG packet header")
	}
	if kind == 3 {
		wire = r.order.Uint32(body[:4])
		caplen = wire
	} else {
		iface = r.order.Uint32(body[:4])
		if kind == 2 {
			iface = uint32(r.order.Uint16(body[:2]))
		}
		stamp = uint64(r.order.Uint32(body[4:8]))<<32 | uint64(r.order.Uint32(body[8:12]))
		caplen, wire = r.order.Uint32(body[12:16]), r.order.Uint32(body[16:20])
	}
	if uint64(iface) >= uint64(len(r.interfaces)) || !r.interfaces[iface].valid {
		return bad(fmt.Sprintf("PCAPNG packet references absent/invalid interface %d", iface))
	}
	intf := r.interfaces[iface]
	if kind == 3 && intf.snaplen != 0 && caplen > intf.snaplen {
		caplen = intf.snaplen
	}
	if caplen > maxInputPacket || caplen > wire || uint64(header)+((uint64(caplen)+3)&^3) > uint64(len(body)) {
		return bad(fmt.Sprintf("invalid PCAPNG packet lengths caplen=%d origlen=%d block-body=%d (packet cap %d)", caplen, wire, len(body), maxInputPacket))
	}
	end := header + (int(caplen)+3)&^3
	if kind == 3 && end != len(body) {
		return bad("PCAPNG simple packet length disagrees with interface snaplen/origlen")
	}
	if kind != 3 {
		if err := ngOptions(body[end:], r.order, nil); err != nil {
			return bad(err.Error())
		}
		secs := stamp / intf.units
		if secs > math.MaxInt64 || (intf.offset > 0 && secs > uint64(math.MaxInt64-intf.offset)) {
			return bad("PCAPNG timestamp overflow")
		}
		hi, lo := bits.Mul64(stamp%intf.units, 1_000_000_000)
		nanos, _ := bits.Div64(hi, lo, intf.units)
		ci.Timestamp = time.Unix(int64(secs)+intf.offset, int64(nanos)).UTC()
	}
	ci.CaptureLength, ci.Length, ci.InterfaceIndex = int(caplen), int(wire), r.interfaceBase+int(iface)
	ci.AncillaryData = []any{intf.link, capturePacketInfo{Order: r.order, Offset: offset, SnaplenOverride: intf.snaplen != 0 && caplen > intf.snaplen, NoTimestamp: kind == 3}}
	return body[header : header+int(caplen)], ci, nil
}

func (r *scopedNgReader) ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	for {
		kind, body, offset, err := r.block()
		if err != nil {
			return nil, gopacket.CaptureInfo{}, err
		}
		switch kind {
		case ngSection:
			err = r.section(body, offset)
		case 1:
			err = r.addInterface(body, offset)
		case 2, 3, 6:
			return r.packet(kind, body, offset)
		case 10: // Decryption Secrets Block, TLS key log (TLSK).
			if len(body) < 8 {
				return nil, gopacket.CaptureInfo{}, fmt.Errorf("short decryption secrets block")
			}
			size := r.order.Uint32(body[4:])
			if size > uint32(len(body)-8) || size > 4<<20 {
				return nil, gopacket.CaptureInfo{}, fmt.Errorf("invalid decryption secrets length")
			}
			if r.order.Uint32(body) == 0x544c534b && r.keyLog != nil {
				r.keyLog(body[8 : 8+int(size)])
			}
		}
		if err != nil {
			return nil, gopacket.CaptureInfo{}, err
		}
	}
}

func (r *scopedNgReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := r.ZeroCopyReadPacketData()
	if err == nil {
		data = append([]byte(nil), data...)
	}
	return data, ci, err
}
