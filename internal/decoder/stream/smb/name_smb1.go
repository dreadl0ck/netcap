package smb

import (
	"encoding/binary"
	"unicode"
	"unicode/utf16"
)

// NameLength is bytes, excluding alignment padding and any trailing terminator.
// The alignment origin is the SMB header, including for an AndX subcommand.
func smb1CreateName(params, data []byte, absolute int, flags2 uint16) string {
	if len(params) != 48 {
		return ""
	}
	n := int(binary.LittleEndian.Uint16(params[5:]))
	wide := flags2&0x8000 != 0
	if wide && absolute%2 != 0 {
		if len(data) == 0 {
			return ""
		}
		data = data[1:]
	}
	if n == 0 || n > len(data) {
		return ""
	}
	return smb1NameBytes(data[:n], wide)
}

func smb1NameBytes(data []byte, wide bool) string {
	if !wide {
		// An unspecified OEM codepage cannot be decoded as UTF-8 or UTF-16.
		for _, c := range data {
			if c < 0x20 || c > 0x7e {
				return ""
			}
		}
		return string(data)
	}
	if len(data)%2 != 0 {
		return ""
	}
	u := make([]uint16, len(data)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(data[2*i:])
	}
	for i := 0; i < len(u); i++ {
		if u[i] >= 0xd800 && u[i] <= 0xdbff {
			if i+1 == len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
				return ""
			}
			i++
		} else if u[i] >= 0xdc00 && u[i] <= 0xdfff {
			return ""
		}
	}
	name := string(utf16.Decode(u))
	for _, r := range name {
		if unicode.IsControl(r) {
			return ""
		}
	}
	return name
}

// SMB strings are aligned relative to the header, not the data section.
func smb1TerminatedName(data []byte, absolute int, flags2 uint16) string {
	wide := flags2&0x8000 != 0
	if wide && absolute%2 != 0 {
		if len(data) == 0 {
			return ""
		}
		data = data[1:]
	}
	width := 1
	if wide {
		width = 2
	}
	for i := 0; i+width <= len(data); i += width {
		if data[i] == 0 && (width == 1 || data[i+1] == 0) {
			return smb1NameBytes(data[:i], wide)
		}
	}
	return ""
}

func smb1TreePath(params, data []byte, absolute int, flags2 uint16) string {
	if len(params) != 8 {
		return ""
	}
	password := int(binary.LittleEndian.Uint16(params[6:]))
	if password > len(data) {
		return ""
	}
	return smb1TerminatedName(data[password:], absolute+password, flags2)
}

func smb1Path(data []byte, absolute int, flags2 uint16, format bool) string {
	if format {
		if len(data) == 0 || data[0] != 4 {
			return ""
		}
		data, absolute = data[1:], absolute+1
	}
	return smb1TerminatedName(data, absolute, flags2)
}
