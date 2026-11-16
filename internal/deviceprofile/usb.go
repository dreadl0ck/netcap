package deviceprofile

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

func USBDescriptor(kind byte, data []byte) (map[string]any, error) {
	fields := map[string]any{"DescriptorType": kind}
	if len(data) < 2 || int(data[0]) > len(data) || data[0] < 2 || data[1] != kind {
		return nil, fmt.Errorf("invalid USB descriptor length/type")
	}
	switch kind {
	case 1:
		if data[0] < 18 {
			return nil, fmt.Errorf("short USB device descriptor")
		}
		fields["USBBCD"], fields["DeviceClass"], fields["DeviceSubclass"], fields["DeviceProtocol"], fields["VendorID"], fields["ProductID"], fields["DeviceBCD"], fields["Configurations"] = binary.LittleEndian.Uint16(data[2:]), data[4], data[5], data[6], binary.LittleEndian.Uint16(data[8:]), binary.LittleEndian.Uint16(data[10:]), binary.LittleEndian.Uint16(data[12:]), data[17]
	case 2:
		if data[0] < 9 {
			return nil, fmt.Errorf("short USB configuration descriptor")
		}
		total := int(binary.LittleEndian.Uint16(data[2:]))
		if total > len(data) || total < 9 {
			return nil, fmt.Errorf("truncated USB configuration")
		}
		fields["Configuration"], fields["Interfaces"], fields["Attributes"], fields["MaxPower2mA"] = data[5], data[4], data[7], data[8]
		var descriptors []map[string]any
		for offset, count := 0, 0; offset < total; count++ {
			if count >= 128 || total-offset < 2 || data[offset] < 2 || int(data[offset]) > total-offset {
				return nil, fmt.Errorf("invalid USB configuration descriptor chain")
			}
			d := data[offset : offset+int(data[offset])]
			item := map[string]any{"Type": d[1], "Length": len(d)}
			if d[1] == 4 && len(d) >= 9 {
				item["Interface"], item["Alternate"], item["Class"], item["Subclass"], item["Protocol"], item["Endpoints"] = d[2], d[3], d[5], d[6], d[7], d[4]
			}
			if d[1] == 5 && len(d) >= 7 {
				item["Endpoint"], item["Attributes"], item["MaxPacketSize"], item["Interval"] = d[2], d[3], binary.LittleEndian.Uint16(d[4:]), d[6]
			}
			descriptors = append(descriptors, item)
			offset += len(d)
		}
		fields["Descriptors"] = descriptors
	case 3:
		if data[0]&1 != 0 {
			return nil, fmt.Errorf("odd USB string descriptor length")
		}
		var code []uint16
		for offset := 2; offset < int(data[0]); offset += 2 {
			code = append(code, binary.LittleEndian.Uint16(data[offset:]))
		}
		fields["UTF16String"] = string(utf16.Decode(code))
	default:
		fields["PayloadLength"] = len(data)
		fields["ProfileStatus"] = "descriptor-class-not-decoded"
	}
	return fields, nil
}

func HIDReportDescriptor(data []byte) (map[string]any, error) {
	if len(data) > 4096 {
		return nil, fmt.Errorf("HID report descriptor exceeds 4096 bytes")
	}
	type globals struct{ size, count, id, page uint32 }
	state := globals{}
	var stack []globals
	reports := map[uint32]map[string]uint32{}
	items := 0
	for offset := 0; offset < len(data); items++ {
		if items >= 1024 {
			return nil, fmt.Errorf("HID item limit exceeded")
		}
		prefix := data[offset]
		offset++
		if prefix == 0xfe {
			if len(data)-offset < 2 {
				return nil, fmt.Errorf("short HID long item")
			}
			size := int(data[offset])
			offset += 2
			if size > len(data)-offset {
				return nil, fmt.Errorf("HID long item exceeds descriptor")
			}
			offset += size
			continue
		}
		size := int(prefix & 3)
		if size == 3 {
			size = 4
		}
		if size > len(data)-offset {
			return nil, fmt.Errorf("short HID item")
		}
		var value uint32
		for i := size - 1; i >= 0; i-- {
			value = value<<8 | uint32(data[offset+i])
		}
		offset += size
		kind, tag := prefix>>2&3, prefix>>4
		if kind == 1 {
			switch tag {
			case 0:
				state.page = value
			case 7:
				state.size = value
			case 8:
				if value == 0 || value > 255 {
					return nil, fmt.Errorf("invalid HID report ID")
				}
				state.id = value
			case 9:
				state.count = value
			case 10:
				if len(stack) >= 16 {
					return nil, fmt.Errorf("HID global stack limit")
				}
				stack = append(stack, state)
			case 11:
				if len(stack) == 0 {
					return nil, fmt.Errorf("HID global stack underflow")
				}
				state = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
		}
		if kind == 0 && (tag == 8 || tag == 9 || tag == 11) {
			if state.size > 64 || state.count > 1024 || uint64(state.size)*uint64(state.count) > 65536 {
				return nil, fmt.Errorf("HID report bit limit exceeded")
			}
			name := map[byte]string{8: "InputBits", 9: "OutputBits", 11: "FeatureBits"}[tag]
			if reports[state.id] == nil {
				if len(reports) >= 64 {
					return nil, fmt.Errorf("HID report count limit")
				}
				reports[state.id] = map[string]uint32{}
			}
			bits := state.size * state.count
			if reports[state.id][name] > 65536-bits {
				return nil, fmt.Errorf("HID report bit limit exceeded")
			}
			reports[state.id][name] += bits
		}
	}
	return map[string]any{"Reports": reports, "Items": items}, nil
}
