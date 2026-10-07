package protocoltest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type Framing struct {
	Kind                 string `json:"kind"`
	LengthBytes          int    `json:"lengthBytes,omitempty"`
	ByteOrder            string `json:"byteOrder,omitempty"`
	LengthIncludesHeader bool   `json:"lengthIncludesHeader,omitempty"`
	Delimiter            []byte `json:"delimiter,omitempty"`
	FixedSize            int    `json:"fixedSize,omitempty"`
	MaxBytes             int    `json:"maxBytes"`
}

func (f Framing) Validate() error {
	if f.MaxBytes < 1 || f.MaxBytes > 1<<20 {
		return fmt.Errorf("maxBytes must be 1..1048576")
	}
	switch f.Kind {
	case "length-prefix":
		if f.LengthBytes != 1 && f.LengthBytes != 2 && f.LengthBytes != 4 {
			return fmt.Errorf("lengthBytes must be 1, 2 or 4")
		}
		if f.ByteOrder != "big" && f.ByteOrder != "little" {
			return fmt.Errorf("byteOrder must be big or little")
		}
	case "delimiter":
		if len(f.Delimiter) < 1 || len(f.Delimiter) > 64 {
			return fmt.Errorf("delimiter must contain 1..64 bytes")
		}
	case "fixed":
		if f.FixedSize < 1 || f.FixedSize > f.MaxBytes {
			return fmt.Errorf("invalid fixed frame size")
		}
	default:
		return fmt.Errorf("unsupported framing kind %q", f.Kind)
	}
	return nil
}

func (f Framing) Read(reader io.Reader) ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	switch f.Kind {
	case "fixed":
		data := make([]byte, f.FixedSize)
		n, err := io.ReadFull(reader, data)
		return data[:n], err
	case "delimiter":
		data := make([]byte, 0, 256)
		var b [1]byte
		for len(data) < f.MaxBytes {
			if _, err := io.ReadFull(reader, b[:]); err != nil {
				return data, err
			}
			data = append(data, b[0])
			if bytes.HasSuffix(data, f.Delimiter) {
				return data, nil
			}
		}
		return data, fmt.Errorf("delimiter frame limit exceeded")
	default:
		header := make([]byte, f.LengthBytes)
		if n, err := io.ReadFull(reader, header); err != nil {
			return header[:n], err
		}
		var order binary.ByteOrder = binary.BigEndian
		if f.ByteOrder == "little" {
			order = binary.LittleEndian
		}
		var length uint32
		switch f.LengthBytes {
		case 1:
			length = uint32(header[0])
		case 2:
			length = uint32(order.Uint16(header))
		case 4:
			length = order.Uint32(header)
		}
		if f.LengthIncludesHeader {
			if length < uint32(f.LengthBytes) {
				return header, fmt.Errorf("length smaller than header")
			}
			length -= uint32(f.LengthBytes)
		}
		if uint64(length)+uint64(f.LengthBytes) > uint64(f.MaxBytes) {
			return header, fmt.Errorf("declared frame exceeds maxBytes")
		}
		body := make([]byte, int(length))
		n, err := io.ReadFull(reader, body)
		return append(header, body[:n]...), err
	}
}

// ParseAll rejects trailing partial frames instead of accepting a plausible prefix.
func (f Framing) ParseAll(data []byte) ([][]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	reader := bytes.NewReader(data)
	frames := [][]byte{}
	for reader.Len() > 0 {
		if len(frames) >= 65536 {
			return nil, fmt.Errorf("frame count limit exceeded")
		}
		frame, err := f.Read(reader)
		if err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}
