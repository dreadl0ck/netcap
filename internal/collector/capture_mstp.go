package collector

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
)

// RFC 8163 Appendix B: encoded zero is 0x55; a 255 code has no implied zero.
func decodeMSTPCOBS(wire []byte) ([]byte, error) {
	if len(wire) == 0 || len(wire) > 2045 {
		return nil, fmt.Errorf("MS/TP COBS field length outside bounds")
	}
	out := make([]byte, 0, len(wire))
	for offset := 0; offset < len(wire); {
		code := int(wire[offset] ^ 0x55)
		if code == 0 || code > len(wire)-offset {
			return nil, fmt.Errorf("invalid MS/TP COBS code at %d", offset)
		}
		offset++
		for range code - 1 {
			value := wire[offset] ^ 0x55
			if value == 0 {
				return nil, fmt.Errorf("encoded zero in MS/TP COBS data at %d", offset)
			}
			out = append(out, value)
			offset++
		}
		if code != 255 && offset < len(wire) {
			out = append(out, 0)
		}
	}
	return out, nil
}

func mstpCRC32K(wire []byte) uint32 {
	crc := uint32(0xffffffff)
	for _, value := range wire {
		crc ^= uint32(value)
		for range 8 {
			bit := crc & 1
			crc >>= 1
			if bit != 0 {
				crc ^= 0xeb31d82e
			}
		}
	}
	return ^crc
}

func decodeMSTPExtended(f *linkaudit.LinkFrame, wire []byte) {
	data, err := decodeMSTPCOBS(wire[:len(wire)-5])
	crc, crcErr := decodeMSTPCOBS(wire[len(wire)-5:])
	valid := err == nil && crcErr == nil && len(crc) == 4
	f.Fields["cobs_valid"] = strconv.FormatBool(valid)
	if !valid {
		f.Qualifications = append(f.Qualifications, "invalid-MS/TP-COBS")
		return
	}
	f.Fields["data_crc32k"] = fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(crc))
	valid = binary.LittleEndian.Uint32(crc) == mstpCRC32K(wire[:len(wire)-5])
	f.Fields["data_crc32k_valid"] = strconv.FormatBool(valid)
	f.Fields["decoded_payload_length"] = strconv.Itoa(len(data))
	f.Decoded = data
	if !valid {
		f.Qualifications = append(f.Qualifications, "invalid-MS/TP-data-CRC32K")
	}
}
