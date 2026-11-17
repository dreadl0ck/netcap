package collector

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

const (
	maxInputPacket     = 1 << 20
	maxInputBlock      = 16 << 20
	maxInputInterfaces = 4096
)

// Offsets refer to the decompressed stream. Recoverable means the entire bounded
// record was consumed; callers must never retry an unread or ambiguous payload.
type captureReadError struct {
	Ordinal     uint64
	Offset      int64
	Reason      string
	Recoverable bool
}

func (e *captureReadError) Error() string {
	return fmt.Sprintf("capture offset %d: %s (recoverable=%t)", e.Offset, e.Reason, e.Recoverable)
}

type capturePacketInfo struct {
	Source              evidence.SourcePacket
	FCSKnown            bool
	FCSBytes            int
	TimestampNormalized bool
	Order               binary.ByteOrder
	Offset              int64
	SnaplenOverride     bool
	NoTimestamp         bool
}

type captureReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

type captureStream struct {
	r      io.Reader
	offset int64
	failed error
}

func newCaptureStream(input io.Reader) (*captureStream, error) {
	r := bufio.NewReader(input)
	magic, _ := r.Peek(2)
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		return &captureStream{r: gz}, nil
	}
	return &captureStream{r: r}, nil
}

func (s *captureStream) read(data []byte) error {
	n, err := io.ReadFull(s.r, data)
	s.offset += int64(n)
	return err
}

func (s *captureStream) fail(offset int64, reason string, recoverable bool) error {
	err := &captureReadError{Offset: offset, Reason: reason, Recoverable: recoverable}
	if !recoverable {
		s.failed = err
	}
	return err
}

func (s *captureStream) failPacket(offset int64, reason string, recoverable bool, ordinal uint64) error {
	err := s.fail(offset, reason, recoverable)
	err.(*captureReadError).Ordinal = ordinal
	return err
}

func captureByteOrder(order binary.ByteOrder) string {
	if order == binary.BigEndian {
		return "big"
	}
	return "little"
}

type boundedPCAPReader struct {
	*captureStream
	order    binary.ByteOrder
	nanos    bool
	patched  bool
	fcsKnown bool
	fcsBytes int
	minor    uint16
	snaplen  uint32
	link     layers.LinkType
	buffer   []byte
	ordinal  uint64
}

func newBoundedPCAPReader(input io.Reader) (*boundedPCAPReader, error) {
	s, err := newCaptureStream(input)
	if err != nil {
		return nil, err
	}
	r := &boundedPCAPReader{captureStream: s}
	var header [24]byte
	if err := r.read(header[:]); err != nil {
		return nil, fmt.Errorf("PCAP global header: %w", err)
	}
	switch binary.LittleEndian.Uint32(header[:4]) {
	case 0xa1b2c3d4:
		r.order = binary.LittleEndian
	case 0xd4c3b2a1:
		r.order = binary.BigEndian
	case 0xa1b23c4d:
		r.order, r.nanos = binary.LittleEndian, true
	case 0x4d3cb2a1:
		r.order, r.nanos = binary.BigEndian, true
	case 0xa1b2cd34:
		r.order, r.patched = binary.LittleEndian, true
	case 0x34cdb2a1:
		r.order, r.patched = binary.BigEndian, true
	default:
		return nil, fmt.Errorf("unknown PCAP magic %x", header[:4])
	}
	major, minor := r.order.Uint16(header[4:6]), r.order.Uint16(header[6:8])
	if major != 2 || minor > 4 {
		return nil, fmt.Errorf("unsupported PCAP version %d.%d (require 2.0–2.4)", major, minor)
	}
	r.minor = minor
	r.snaplen = r.order.Uint32(header[16:20])
	// The upper 16 bits are additional information, not part of LINKTYPE.
	r.link = layers.LinkType(r.order.Uint32(header[20:24]) & 0xffff)
	word := r.order.Uint32(header[20:24])
	r.fcsKnown = word&0x04000000 != 0
	if r.fcsKnown {
		r.fcsBytes = int(word>>28) * 2
	}
	return r, nil
}

func (r *boundedPCAPReader) LinkType() layers.LinkType { return r.link }

func (r *boundedPCAPReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return r.readPacket(false)
}

func (r *boundedPCAPReader) ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return r.readPacket(true)
}

func (r *boundedPCAPReader) readPacket(reuse bool) ([]byte, gopacket.CaptureInfo, error) {
	var ci gopacket.CaptureInfo
	if r.failed != nil {
		return nil, ci, r.failed
	}
	offset := r.offset
	var header [24]byte
	headerSize := 16
	if r.patched {
		headerSize = 24
	}
	if err := r.read(header[:headerSize]); err != nil {
		if err == io.EOF && r.offset == offset {
			return nil, ci, io.EOF
		}
		return nil, ci, r.fail(offset, fmt.Sprintf("PCAP record header: %v", err), false)
	}
	caplen, wire := r.order.Uint32(header[8:12]), r.order.Uint32(header[12:16])
	if r.ordinal == ^uint64(0) {
		return nil, ci, r.fail(offset, "PCAP packet ordinal exhausted", false)
	}
	r.ordinal++
	// libpcap sf-pcap.c: pre-2.3 lengths are reversed; 2.3 exists in both orders.
	if r.minor < 3 || r.minor == 3 && caplen > wire {
		caplen, wire = wire, caplen
	}
	if caplen > maxInputPacket {
		return nil, ci, r.failPacket(offset, fmt.Sprintf("PCAP caplen %d exceeds hard packet cap %d", caplen, maxInputPacket), false, r.ordinal)
	}
	data := r.buffer
	if !reuse || cap(data) < int(caplen) {
		data = make([]byte, int(caplen))
	}
	data = data[:int(caplen)]
	if reuse {
		r.buffer = data
	}
	if err := r.read(data); err != nil {
		return nil, ci, r.failPacket(offset, fmt.Sprintf("truncated PCAP payload: %v", err), false, r.ordinal)
	}
	if caplen > wire {
		return nil, ci, r.failPacket(offset, fmt.Sprintf("PCAP caplen %d exceeds origlen %d", caplen, wire), true, r.ordinal)
	}
	frac, units := r.order.Uint32(header[4:8]), uint32(1_000_000)
	if r.nanos {
		units = 1_000_000_000
	}
	ci.Timestamp = time.Unix(int64(r.order.Uint32(header[:4])), int64(frac)*int64(1_000_000_000/units)).UTC()
	ci.CaptureLength, ci.Length = int(caplen), int(wire)
	source := evidence.SourcePacket{Ordinal: r.ordinal, Offset: offset, OffsetNamespace: evidence.SourceOffsetNamespace, OffsetKind: "record-header", ByteOrder: captureByteOrder(r.order), TimestampEncoding: "seconds-fraction", TimestampSeconds: uint64(r.order.Uint32(header[:4])), TimestampFraction: frac, TimestampUnits: uint64(units)}
	ci.AncillaryData = []any{r.link, capturePacketInfo{Source: source, Order: r.order, Offset: offset, SnaplenOverride: caplen > r.snaplen, TimestampNormalized: frac >= units, FCSKnown: r.fcsKnown, FCSBytes: r.fcsBytes}}
	return data, ci, nil
}

func inputPacketInfo(ci gopacket.CaptureInfo) capturePacketInfo {
	for _, value := range ci.AncillaryData {
		if info, ok := value.(capturePacketInfo); ok {
			return info
		}
	}
	return capturePacketInfo{}
}
