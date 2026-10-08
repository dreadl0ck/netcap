package protocoltest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// ErrBudgetExceeded denotes a harness limit, never a target rejection or crash.
var ErrBudgetExceeded = errors.New("harness budget exceeded")

type LengthField struct {
	Offset     int    `json:"offset"`
	Width      int    `json:"width"`
	ByteOrder  string `json:"byteOrder"`
	Adjustment int    `json:"adjustment"`
}

func (s LengthField) Validate() error {
	if s.Offset < 0 || s.Offset > 1<<20 || !validWidth(s.Width) || (s.ByteOrder != "big" && s.ByteOrder != "little") || s.Adjustment < -4096 || s.Adjustment > 4096 {
		return fmt.Errorf("invalid variable-length hypothesis")
	}
	return nil
}
func (s LengthField) Resolve(frame []byte) (int, error) {
	if err := s.Validate(); err != nil {
		return 0, err
	}
	if s.Offset > len(frame) || s.Width > len(frame)-s.Offset {
		return 0, fmt.Errorf("truncated length field")
	}
	n := int64(readNumber(frame[s.Offset:s.Offset+s.Width], s.ByteOrder)) + int64(s.Adjustment)
	if n < 0 {
		return 0, fmt.Errorf("negative adjusted field length")
	}
	if n > 4096 {
		return 0, fmt.Errorf("%w: variable field length", ErrBudgetExceeded)
	}
	return int(n), nil
}
func validWidth(n int) bool { return n == 1 || n == 2 || n == 4 }
func readNumber(b []byte, order string) uint64 {
	var padded [8]byte
	if order == "little" {
		copy(padded[:], b)
		return binary.LittleEndian.Uint64(padded[:])
	}
	copy(padded[8-len(b):], b)
	return binary.BigEndian.Uint64(padded[:])
}

type TLVSpec struct {
	TypeBytes            int      `json:"typeBytes"`
	LengthBytes          int      `json:"lengthBytes"`
	ByteOrder            string   `json:"byteOrder"`
	LengthIncludesHeader bool     `json:"lengthIncludesHeader"`
	NestedTypes          []uint64 `json:"nestedTypes,omitempty"`
	LeafKind             string   `json:"leafKind"`
	MaxDepth             int      `json:"maxDepth"`
	MaxEntries           int      `json:"maxEntries"`
	MaxValueBytes        int      `json:"maxValueBytes"`
}
type TLVEntry struct {
	Type     uint64     `json:"type"`
	Offset   int        `json:"offset"`
	Length   int        `json:"length"`
	Value    []byte     `json:"value"`
	Children []TLVEntry `json:"children,omitempty"`
}

func (s TLVSpec) Validate() error {
	if !validWidth(s.TypeBytes) || !validWidth(s.LengthBytes) || (s.ByteOrder != "big" && s.ByteOrder != "little") || (s.LeafKind != "bytes" && s.LeafKind != "utf8") || s.MaxDepth < 1 || s.MaxDepth > 8 || s.MaxEntries < 1 || s.MaxEntries > 1024 || s.MaxValueBytes < 1 || s.MaxValueBytes > 4096 || len(s.NestedTypes) > 32 {
		return fmt.Errorf("unsupported TLV hypothesis or invalid limits")
	}
	seen := map[uint64]bool{}
	for _, tag := range s.NestedTypes {
		if tag > (uint64(1)<<uint(s.TypeBytes*8))-1 || seen[tag] {
			return fmt.Errorf("invalid/duplicate nested TLV tag")
		}
		seen[tag] = true
	}
	return nil
}
func interpretTLV(data []byte, offset int, s TLVSpec, reportBudget *int) ([]TLVEntry, error) {
	entries := 0
	var parse func([]byte, int, int) ([]TLVEntry, error)
	parse = func(data []byte, base, depth int) ([]TLVEntry, error) {
		if len(data) == 0 {
			return []TLVEntry{}, nil
		}
		if depth > s.MaxDepth {
			return nil, fmt.Errorf("%w: TLV nesting depth", ErrBudgetExceeded)
		}
		out := []TLVEntry{}
		header := s.TypeBytes + s.LengthBytes
		for cursor := 0; cursor < len(data); {
			if entries >= s.MaxEntries {
				return out, fmt.Errorf("%w: TLV entry count", ErrBudgetExceeded)
			}
			if len(data)-cursor < header {
				return out, fmt.Errorf("truncated TLV header at %d", base+cursor)
			}
			tag := readNumber(data[cursor:cursor+s.TypeBytes], s.ByteOrder)
			n := readNumber(data[cursor+s.TypeBytes:cursor+header], s.ByteOrder)
			if s.LengthIncludesHeader {
				if n < uint64(header) {
					return out, fmt.Errorf("TLV length smaller than header")
				}
				n -= uint64(header)
			}
			if n > uint64(s.MaxValueBytes) {
				return out, fmt.Errorf("%w: TLV value bytes", ErrBudgetExceeded)
			}
			if n > uint64(len(data)-cursor-header) {
				return out, fmt.Errorf("truncated TLV value at %d", base+cursor)
			}
			value := data[cursor+header : cursor+header+int(n)]
			cost := 128 + len(value)
			if cost > *reportBudget {
				return out, fmt.Errorf("%w: TLV report allocation", ErrBudgetExceeded)
			}
			*reportBudget -= cost
			entries++
			entry := TLVEntry{Type: tag, Offset: base + cursor, Length: header + int(n), Value: append([]byte{}, value...)}
			nested := false
			for _, candidate := range s.NestedTypes {
				if tag == candidate {
					nested = true
					break
				}
			}
			if nested {
				children, err := parse(value, base+cursor+header, depth+1)
				entry.Children = children
				if err != nil {
					return append(out, entry), err
				}
			} else if s.LeafKind == "utf8" && !utf8.Valid(value) {
				return out, fmt.Errorf("invalid UTF-8 TLV value at %d", base+cursor)
			}
			out = append(out, entry)
			cursor += header + int(n)
		}
		return out, nil
	}
	return parse(data, offset, 1)
}
