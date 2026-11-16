package collector

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/dreadl0ck/netcap/internal/bacnet"
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

func decodeMSTPNPDU(f *linkaudit.LinkFrame, kind byte, body []byte) {
	if f.Fields["header_crc_valid"] != "true" {
		return
	}
	if kind == 5 || kind == 6 {
		if f.Fields["data_crc_valid"] != "true" {
			return
		}
	} else if kind == 32 || kind == 33 {
		if f.Fields["cobs_valid"] != "true" || f.Fields["data_crc32k_valid"] != "true" {
			return
		}
		body = f.Decoded
	} else {
		return
	}
	pdu, err := bacnet.ParseNPDU(body)
	if err != nil {
		f.Qualifications = append(f.Qualifications, "invalid-BACnet-NPDU-or-APDU")
		return
	}
	wire, _ := json.Marshal(pdu)
	f.Fields["bacnet_npdu"] = string(wire)
	f.Decoded = bytes.Clone(body)
	markLinkDecoded(f, "BACnet-NPDU")
	if pdu.APDU != nil {
		f.Qualifications = append(f.Qualifications, pdu.APDU.Qualifications...)
	}
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
