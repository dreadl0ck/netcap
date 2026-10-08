package evidence

import (
	"encoding/binary"
	"fmt"
	"io"
)

const maxCapturedPacket = 1 << 20
const maxCaptureBlock = 16 << 20

// Validate lengths before pcapgo allocates packet or metadata buffers.
type guardedNGReader struct {
	input     io.Reader
	order     binary.ByteOrder
	prefix    []byte
	remaining int64
	metadata  int64
}

func (r *guardedNGReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.prefix) > 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		return n, nil
	}
	if r.remaining > 0 {
		if int64(len(p)) > r.remaining {
			p = p[:int(r.remaining)]
		}
		n, err := r.input.Read(p)
		r.remaining -= int64(n)
		if err == io.EOF && r.remaining > 0 {
			err = io.ErrUnexpectedEOF
		}
		return n, err
	}
	header := make([]byte, 8)
	if _, err := io.ReadFull(r.input, header); err != nil {
		return 0, err
	}
	section := binary.BigEndian.Uint32(header[:4]) == 0x0a0d0d0a
	if section {
		magic := make([]byte, 4)
		if _, err := io.ReadFull(r.input, magic); err != nil {
			return 0, err
		}
		header = append(header, magic...)
		switch binary.BigEndian.Uint32(magic) {
		case 0x1a2b3c4d:
			r.order = binary.BigEndian
		case 0x4d3c2b1a:
			r.order = binary.LittleEndian
		default:
			return 0, fmt.Errorf("invalid PCAPNG byte order")
		}
	}
	if r.order == nil {
		return 0, fmt.Errorf("PCAPNG must start with a section")
	}
	size, kind := r.order.Uint32(header[4:8]), r.order.Uint32(header[:4])
	if size > maxCaptureBlock || size < uint32(len(header)+4) || size%4 != 0 {
		return 0, fmt.Errorf("invalid or oversized PCAPNG block: %d (limit %d)", size, maxCaptureBlock)
	}
	want := len(header)
	switch kind {
	case 2, 6:
		want = 28
	case 3:
		want = 12
	}
	if size < uint32(want+4) {
		return 0, fmt.Errorf("truncated PCAPNG packet header")
	}
	if want > len(header) {
		extra := make([]byte, want-len(header))
		if _, err := io.ReadFull(r.input, extra); err != nil {
			return 0, err
		}
		header = append(header, extra...)
	}
	if kind == 2 || kind == 6 {
		captured, wire := r.order.Uint32(header[20:24]), r.order.Uint32(header[24:28])
		if captured > maxCapturedPacket || captured > size-32 || wire < captured {
			return 0, fmt.Errorf("invalid or oversized PCAPNG packet length: captured=%d wire=%d", captured, wire)
		}
	} else if kind == 3 {
		if wire := r.order.Uint32(header[8:12]); wire > maxCapturedPacket {
			return 0, fmt.Errorf("oversized PCAPNG simple packet length: %d", wire)
		}
	} else {
		r.metadata += int64(size)
		if r.metadata > maxCaptureBlock {
			return 0, fmt.Errorf("PCAPNG metadata limit exceeded: %d", maxCaptureBlock)
		}
	}
	r.prefix, r.remaining = header, int64(size)-int64(len(header))
	return r.Read(p)
}
