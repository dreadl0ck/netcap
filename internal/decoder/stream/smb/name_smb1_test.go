package smb

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func ntCreateParameters(n int) []byte {
	p := make([]byte, 48)
	p[0] = 0xff
	binary.LittleEndian.PutUint16(p[5:], uint16(n))
	binary.LittleEndian.PutUint32(p[15:], 0x0012019f)
	binary.LittleEndian.PutUint32(p[27:], 0x80)
	binary.LittleEndian.PutUint32(p[35:], 3)
	binary.LittleEndian.PutUint32(p[39:], 0x40)
	return p
}

func TestSMB1NTCreateNamesAndOffsets(t *testing.T) {
	for _, name := range []string{"\\lsarpc", "\\PIPE\\srvsvc", "file.txt", "档案-🎵.txt"} {
		for _, wide := range []bool{false, true} {
			if !wide && name == "档案-🎵.txt" {
				continue
			}
			for _, at := range []int{83, 120} {
				data, flags := []byte(name), uint16(0)
				if wide {
					data, flags = nil, 0x8000
					for _, u := range utf16.Encode([]rune(name)) {
						data = binary.LittleEndian.AppendUint16(data, u)
					}
				}
				p := ntCreateParameters(len(data))
				if wide && at%2 != 0 {
					data = append([]byte{0}, data...)
				}
				data = append(data, []byte("trailing data outside NameLength")...)
				s := newTestSMBReader()
				s.parseSMB1NTCreate(p, data, false, flags, at)
				if s.filename != name || s.accessMask != 0x0012019f || s.createDisp != 3 || s.fileAttributes != 0x80 || s.isDirectory {
					t.Fatalf("%q wide=%v offset=%d: %+v", name, wide, at, s)
				}
			}
		}
	}
	r := make([]byte, 68)
	r[0], r[4], r[11], r[67] = 0xff, 1, 0, 1
	binary.LittleEndian.PutUint16(r[2:], 0x3344) // AndXOffset is not the FID
	binary.LittleEndian.PutUint16(r[5:], 0x1234)
	binary.LittleEndian.PutUint32(r[43:], 0x10)
	s := newTestSMBReader()
	s.parseSMB1NTCreate(r, nil, true, 0, 103)
	if s.fileID != 0x1234 || !s.isDirectory || s.fileAttributes != 0x10 {
		t.Fatal("wrong response parameter offsets", s)
	}
}

func TestSMB1NTCreateMalformedNames(t *testing.T) {
	for _, tc := range []struct {
		data  []byte
		n     int
		flags uint16
		at    int
	}{
		{[]byte{0, '\\', 0, 's'}, 3, 0x8000, 83}, // odd UTF-16 length
		{[]byte{0, '\\', 0}, 4, 0x8000, 83},      // truncated name
		{nil, 2, 0x8000, 83},
		{[]byte{0, 0, 0xd8}, 2, 0x8000, 83}, // unpaired surrogate
		{[]byte{0, 0, 0xdc}, 2, 0x8000, 83},
		{[]byte{0, 'a', 0, 0, 0}, 4, 0x8000, 83}, // embedded NUL
		{[]byte("file\nname"), 9, 0, 83},
		{[]byte{'a', 0, 'b'}, 3, 0, 83}, // ASCII flag must not trigger UTF-16 heuristic
		{[]byte{0xff}, 1, 0, 83},        // unspecified OEM codepage
		{[]byte("file"), 0, 0, 83},
	} {
		if got := smb1CreateName(ntCreateParameters(tc.n), tc.data, tc.at, tc.flags); got != "" {
			t.Fatalf("accepted %x: %q", tc.data, got)
		}
	}
}

func TestSMB1FileTrackerUsesCountedName(t *testing.T) {
	s := newSMB1Files(func(*smbTransfer, []byte) {})
	name := "fixture.txt"
	p := ntCreateParameters(len(name))
	frame := make([]byte, 33)
	copy(frame, "\xffSMB")
	frame[4], frame[24], frame[28], frame[30], frame[32] = 0xa2, 1, 2, 3, 24
	frame = append(frame, p...)
	frame = binary.LittleEndian.AppendUint16(frame, uint16(len(name)+5))
	frame = append(frame, []byte(name+"extra")...)
	s.consume(frame, 123)
	if len(s.pending) != 1 {
		t.Fatal(s.pending)
	}
	for _, r := range s.pending {
		if r.name != name || r.directory {
			t.Fatal(r)
		}
	}
}

func TestSMB1TreeAndLegacyPaths(t *testing.T) {
	for _, wide := range []bool{false, true} {
		for _, absolute := range []int{43, 44} {
			flags := uint16(0)
			encode := func(name string, at int) []byte {
				if !wide {
					return append([]byte(name), 0)
				}
				flags = 0x8000
				var data []byte
				if at%2 != 0 {
					data = append(data, 0)
				}
				for _, u := range utf16.Encode([]rune(name)) {
					data = binary.LittleEndian.AppendUint16(data, u)
				}
				return append(data, 0, 0)
			}
			name := `\\server\share`
			if wide {
				name = `\\server\共享`
			}
			params := make([]byte, 8)
			// Passwords are counted opaque bytes, including embedded NULs.
			password := []byte{0x41, 0, 0x42, 0x43}
			binary.LittleEndian.PutUint16(params[6:], uint16(len(password)))
			data := append(password, encode(name, absolute+len(password))...)
			data = append(data, []byte("IPC\x00unrelated")...)
			if got := smb1TreePath(params, data, absolute, flags); got != name {
				t.Fatalf("wide=%v absolute=%d: %q", wide, absolute, got)
			}
			for _, format := range []bool{false, true} {
				at := absolute
				var data []byte
				if format {
					data = append(data, 4)
					at++
				}
				data = append(data, encode(name, at)...)
				data = append(data, []byte("ignored")...)
				if got := smb1Path(data, absolute, flags, format); got != name {
					t.Fatalf("legacy path wide=%v format=%v: %q", wide, format, got)
				}
			}
			params[6] = 255
			if smb1TreePath(params, data, absolute, flags) != "" {
				t.Fatal("password length escaped data section")
			}
		}
	}
	for _, tc := range []struct {
		data  []byte
		flags uint16
	}{
		{[]byte("unterminated"), 0},
		{[]byte{4, 'a', 0}, 0}, // format byte is not part of a pathname
		{[]byte{0, 0xd8, 0, 0}, 0x8000},
		{[]byte{'a', 0, 0}, 0x8000}, // incomplete terminator
	} {
		if smb1TerminatedName(tc.data, 44, tc.flags) != "" {
			t.Fatalf("accepted malformed name %x", tc.data)
		}
	}
	if smb1Path([]byte{3, 'a', 0}, 44, 0, true) != "" {
		t.Fatal("invalid buffer format accepted")
	}
}

func TestSMB1MessageNamesRespectHeaderAndByteCount(t *testing.T) {
	for _, command := range []byte{SMB1_COM_NT_CREATE_ANDX, SMB1_COM_OPEN_ANDX, SMB1_COM_DELETE, SMB1_COM_TREE_CONNECT_ANDX} {
		name := `\档案-🎵`
		params := make([]byte, 2)
		switch command {
		case SMB1_COM_NT_CREATE_ANDX:
			params = ntCreateParameters(len(utf16.Encode([]rune(name))) * 2)
		case SMB1_COM_OPEN_ANDX:
			params = make([]byte, 30)
		case SMB1_COM_TREE_CONNECT_ANDX:
			name = `\\server\共享`
			params = make([]byte, 8)
			params[6] = 3
		}
		var data []byte
		if command == SMB1_COM_DELETE {
			data = append(data, 4)
		}
		if command == SMB1_COM_TREE_CONNECT_ANDX {
			data = append(data, 0x42, 0, 0x43)
		}
		if (35+len(params)+len(data))%2 != 0 {
			data = append(data, 0)
		}
		for _, u := range utf16.Encode([]rune(name)) {
			data = binary.LittleEndian.AppendUint16(data, u)
		}
		if command != SMB1_COM_NT_CREATE_ANDX {
			data = append(data, 0, 0)
		}
		frame := make([]byte, 33)
		copy(frame, "\xffSMB")
		frame[4], frame[11], frame[24], frame[28], frame[30], frame[32] = command, 0x80, 7, 8, 9, byte(len(params)/2)
		frame = append(frame, params...)
		frame = binary.LittleEndian.AppendUint16(frame, uint16(len(data)))
		frame = append(frame, data...)
		s := newTestSMBReader()
		if err := s.parseSMB1Message(frame, true); err != nil {
			t.Fatal(err)
		}
		got := s.filename
		if command == SMB1_COM_TREE_CONNECT_ANDX {
			got = s.shareName
		}
		if got != name || s.treeID != 7 || s.sessionID != 8 || s.messageID != 9 {
			t.Fatalf("command=%x name=%q", command, got)
		}
		// A truncated ByteCount must not read the complete name from the NBSS tail.
		binary.LittleEndian.PutUint16(frame[33+len(params):], uint16(len(data)+2))
		s = newTestSMBReader()
		if err := s.parseSMB1Message(frame, true); err != nil {
			t.Fatal(err)
		}
		if s.filename != "" || s.shareName != "" {
			t.Fatal("name escaped ByteCount", s.filename, s.shareName)
		}
	}
}

func FuzzSMB1NTCreateName(f *testing.F) {
	f.Add([]byte{0, '\\', 0, 'l', 0, 's', 0, 'a', 0}, uint16(8), true, true)
	f.Add([]byte("file.txt"), uint16(8), false, false)
	f.Fuzz(func(t *testing.T, b []byte, n uint16, wide, odd bool) {
		flags, at := uint16(0), 82
		if wide {
			flags = 0x8000
		}
		if odd {
			at++
		}
		p := ntCreateParameters(int(n))
		name := smb1CreateName(p, b, at, flags)
		if len(name) > 3*int(n) {
			t.Fatal("name escaped counted field")
		}
	})
}
