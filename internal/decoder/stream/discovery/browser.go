package discovery

import (
	"bytes"
	"encoding/binary"
	"strings"
	"time"
)

func browserExtract(data []byte, _ string, _ time.Time) *DiscoveryResult {
	if len(data) < 14 || data[0] < 0x10 || data[0] > 0x12 || data[1]&0x03 != 0x02 {
		return nil
	} // first, unfragmented datagram
	pos := 14
	for range 2 {
		_, _, end := nbnsDecodeName(data, pos)
		if end <= pos {
			return nil
		}
		pos = end
	}
	smb := data[pos:]
	if len(smb) < 67 || !bytes.Equal(smb[:4], []byte{0xff, 'S', 'M', 'B'}) || smb[4] != 0x25 || smb[32] < 17 {
		return nil
	}
	count, offset := int(binary.LittleEndian.Uint16(smb[55:57])), int(binary.LittleEndian.Uint16(smb[57:59]))
	if offset < 67 || count < 22 || offset > len(smb) || count > len(smb)-offset || !bytes.Contains(smb[67:offset], []byte("\\MAILSLOT\\BROWSE\x00")) {
		return nil
	}
	announcement := smb[offset : offset+count]
	if announcement[0] != 1 && announcement[0] != 15 {
		return nil
	} // domain announcements (12) name workgroups
	name := strings.TrimRight(string(announcement[6:22]), " \x00")
	if !nbnsIsValidName(name) {
		return nil
	}
	return &DiscoveryResult{Hostnames: []string{name}, Roles: []string{"Workstation"}}
}
