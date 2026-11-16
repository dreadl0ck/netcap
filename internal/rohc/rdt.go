package rohc

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type Description struct {
	PLP, MaxCID, Mode, Config uint8
	Contexts                  []DescriptionContext
}
type DescriptionContext struct {
	ID, Profile uint8
	ChainLength int
	Chain       []byte `json:"-"`
}

func ParseRDT(data []byte) (Description, error) {
	var d Description
	if len(data) < 4 {
		return d, fmt.Errorf("short ALP RDT")
	}
	word := binary.BigEndian.Uint16(data)
	d.PLP = uint8(word >> 10)
	d.MaxCID = uint8(word >> 2 & 255)
	d.Mode = uint8(word & 3)
	d.Config = data[2] >> 6
	count := int(data[3])
	offset := 4
	if d.MaxCID > 127 || d.Mode == 3 || count > int(d.MaxCID) {
		return d, fmt.Errorf("invalid ALP RDT parameters")
	}
	seen := map[byte]bool{}
	for range count {
		if len(data)-offset < 2 {
			return d, fmt.Errorf("short ALP RDT context")
		}
		entry := DescriptionContext{ID: data[offset], Profile: data[offset+1]}
		offset += 2
		if entry.ID > d.MaxCID || seen[entry.ID] {
			return d, fmt.Errorf("invalid or duplicate ALP RDT CID")
		}
		seen[entry.ID] = true
		if d.Config != 0 {
			if offset == len(data) {
				return d, fmt.Errorf("ALP RDT context length missing")
			}
			entry.ChainLength = int(data[offset])
			offset++
			if entry.ChainLength > len(data)-offset {
				return d, fmt.Errorf("ALP RDT chain exceeds table")
			}
			entry.Chain = bytes.Clone(data[offset : offset+entry.ChainLength])
			offset += entry.ChainLength
		}
		d.Contexts = append(d.Contexts, entry)
	}
	if offset != len(data) {
		return d, fmt.Errorf("ALP RDT has trailing data")
	}
	return d, nil
}

func (d Description) InitialStates() (map[byte]Context, error) {
	states := map[byte]Context{}
	for _, entry := range d.Contexts {
		if entry.Profile != 2 {
			continue
		}
		var c Context
		offset := 0
		var err error
		if d.Config == 1 || d.Config == 3 {
			c, offset, err = Static(entry.Chain)
			if err != nil {
				return nil, err
			}
		}
		if d.Config == 3 {
			var n int
			c, n, err = Dynamic(c, entry.Chain[offset:])
			if err != nil {
				return nil, err
			}
			offset += n
		}
		if d.Config == 1 || d.Config == 3 {
			if offset != len(entry.Chain) {
				return nil, fmt.Errorf("ALP RDT static/dynamic chain length mismatch")
			}
		}
		states[entry.ID] = c
	}
	return states, nil
}

// PacketCID implements the ATSC small/one-octet large CID channel configurations.
func PacketCID(wire []byte, large bool) (id byte, first, after int, err error) {
	if len(wire) == 0 {
		return 0, 0, 0, fmt.Errorf("empty ROHC packet")
	}
	if large {
		if len(wire) < 2 || wire[1]&0x80 != 0 {
			return 0, 0, 0, fmt.Errorf("invalid one-octet ROHC large CID")
		}
		return wire[1], 0, 2, nil
	}
	if wire[0]&0xf0 == 0xe0 {
		if len(wire) < 2 || wire[0]&15 == 0 {
			return 0, 0, 0, fmt.Errorf("invalid ROHC Add-CID")
		}
		return wire[0] & 15, 1, 2, nil
	}
	return 0, 0, 1, nil
}
