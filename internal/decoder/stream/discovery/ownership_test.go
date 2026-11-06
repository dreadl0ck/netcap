package discovery

import (
	"encoding/binary"
	"testing"
	"time"
)

func encodedName(name string, suffix byte) []byte {
	raw := make([]byte, 16)
	for i := range raw {
		raw[i] = ' '
	}
	copy(raw, name)
	raw[15] = suffix
	out := []byte{32}
	for _, b := range raw {
		out = append(out, 'A'+b>>4, 'A'+b&15)
	}
	return append(out, 0)
}

func TestNBNSDoesNotAttributeQueriesOrGroups(t *testing.T) {
	name := encodedName("VICTIM", 0)
	query := make([]byte, 12)
	query[5] = 1
	query = append(query, name...)
	query = append(query, 0, 32, 0, 1)
	if r := nbnsExtract(query, "", time.Time{}); r != nil {
		t.Fatal("query attributed as local hostname", r)
	}
	response := append([]byte(nil), query...)
	response[2] = 0x85
	response[7] = 1
	response = append(response, 0xc0, 12, 0, 32, 0, 1, 0, 0, 0, 60, 0, 6, 0, 0, 192, 0, 2, 1)
	r := nbnsExtract(response, "", time.Time{})
	if r == nil || r.SourceIP != "192.0.2.1" || len(r.Hostnames) != 1 || r.Hostnames[0] != "VICTIM" {
		t.Fatal(r)
	}
	response[len(response)-6] = 0x80
	if r := nbnsExtract(response, "", time.Time{}); r != nil {
		t.Fatal("workgroup claimed as host", r)
	}
}

func TestBrowserDomainAnnouncementIsNotHostname(t *testing.T) {
	for _, command := range []byte{1, 12, 15} {
		header := make([]byte, 14)
		header[0] = 0x11
		header[1] = 2
		header = append(header, encodedName("VICTIM", 0)...)
		header = append(header, encodedName("WORKGROUP", 0x1d)...)
		smb := make([]byte, 67)
		copy(smb, []byte{0xff, 'S', 'M', 'B', 0x25})
		smb[32] = 17
		smb = append(smb, []byte("\\MAILSLOT\\BROWSE\x00")...)
		offset := len(smb)
		body := make([]byte, 22)
		body[0] = command
		copy(body[6:], "VICTIM")
		binary.LittleEndian.PutUint16(smb[55:], uint16(len(body)))
		binary.LittleEndian.PutUint16(smb[57:], uint16(offset))
		smb = append(smb, body...)
		r := browserExtract(append(header, smb...), "", time.Time{})
		if command == 12 {
			if r != nil {
				t.Fatal("domain announcement treated as host")
			}
		} else if r == nil || r.Hostnames[0] != "VICTIM" {
			t.Fatal(r)
		}
	}
}
