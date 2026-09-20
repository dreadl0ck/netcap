/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package collector

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// testPacket is one minimal Ethernet frame: broadcast destination, a source
// address and an unusual ethertype, so it is recognisable in assertions.
var testPacket = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
	0x08, 0x00,
	'n', 'e', 't', 'c', 'a', 'p',
}

// writeClassicPcap builds a classic PCAP file with an explicit version, byte
// order and timestamp resolution, which is the only way to produce the legacy
// versions this package has to keep reading.
func writeClassicPcap(t *testing.T, path string, order binary.ByteOrder, major, minor uint16, nanos bool, tsSec, tsFrac uint32) {
	t.Helper()

	magic := uint32(0xa1b2c3d4)
	if nanos {
		magic = 0xa1b23c4d
	}

	header := make([]byte, 24)
	order.PutUint32(header[0:4], magic)
	order.PutUint16(header[4:6], major)
	order.PutUint16(header[6:8], minor)
	order.PutUint32(header[16:20], 262144)
	order.PutUint32(header[20:24], uint32(layers.LinkTypeEthernet))

	record := make([]byte, 16)
	order.PutUint32(record[0:4], tsSec)
	order.PutUint32(record[4:8], tsFrac)
	order.PutUint32(record[8:12], uint32(len(testPacket)))
	order.PutUint32(record[12:16], uint32(len(testPacket)))

	contents := append(append(header, record...), testPacket...)
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatal(err)
	}
}

// writePcapNG writes a small PCAPNG file using the library's own writer.
func writePcapNG(t *testing.T, path string) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	buffered := bufio.NewWriter(f)

	w, err := pcapgo.NewNgWriter(buffered, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Unix(1, 0),
		CaptureLength: len(testPacket),
		Length:        len(testPacket),
	}

	if err = w.WritePacket(ci, testPacket); err != nil {
		t.Fatal(err)
	}

	if err = w.Flush(); err != nil {
		t.Fatal(err)
	}

	if err = buffered.Flush(); err != nil {
		t.Fatal(err)
	}
}

// TestOpenPCAPVersions covers every classic PCAP variant relevant to the
// corpus. The valid pre-2.4 variants are rejected by the pure Go reader on the
// version field alone, so they must fall through to libpcap.
func TestOpenPCAPVersions(t *testing.T) {
	tests := []struct {
		name        string
		order       binary.ByteOrder
		major       uint16
		minor       uint16
		nanos       bool
		tsFrac      uint32
		wantFrac    time.Duration
		wantLibpcap bool
	}{
		{
			name:     "2.4 little-endian microseconds",
			order:    binary.LittleEndian,
			major:    2,
			minor:    4,
			tsFrac:   500000,
			wantFrac: 500 * time.Millisecond,
		},
		{
			name:     "2.4 big-endian microseconds",
			order:    binary.BigEndian,
			major:    2,
			minor:    4,
			tsFrac:   500000,
			wantFrac: 500 * time.Millisecond,
		},
		{
			name:     "2.4 little-endian nanoseconds",
			order:    binary.LittleEndian,
			major:    2,
			minor:    4,
			nanos:    true,
			tsFrac:   123456789,
			wantFrac: 123456789 * time.Nanosecond,
		},
		{
			// The four nfsv2/nfsv3 captures in the corpus are exactly this.
			name:        "2.1 big-endian microseconds",
			order:       binary.BigEndian,
			major:       2,
			minor:       1,
			tsFrac:      500000,
			wantFrac:    500 * time.Millisecond,
			wantLibpcap: true,
		},
		{
			name:        "2.0 little-endian nanoseconds",
			order:       binary.LittleEndian,
			major:       2,
			minor:       0,
			nanos:       true,
			tsFrac:      123456789,
			wantFrac:    123456789 * time.Nanosecond,
			wantLibpcap: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.pcap")
			writeClassicPcap(t, path, tt.order, tt.major, tt.minor, tt.nanos, 1000, tt.tsFrac)

			format, err := DetectCaptureFormat(path)
			if err != nil {
				t.Fatal(err)
			}

			if format != CaptureFormatPCAP {
				t.Fatalf("format = %v, want PCAP", format)
			}

			isPcap, err := IsPcap(path)
			if err != nil {
				t.Fatal(err)
			}

			if isPcap == tt.wantLibpcap {
				t.Errorf("IsPcap = %v, want %v", isPcap, !tt.wantLibpcap)
			}

			r, err := OpenPCAPReader(path)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()

			if _, isLibpcap := r.(*libpcapReader); isLibpcap != tt.wantLibpcap {
				t.Errorf("libpcap fallback = %v, want %v", isLibpcap, tt.wantLibpcap)
			}

			if r.LinkType() != layers.LinkTypeEthernet {
				t.Errorf("link type = %v, want Ethernet", r.LinkType())
			}

			data, ci, err := r.ReadPacketData()
			if err != nil {
				t.Fatal(err)
			}

			if string(data) != string(testPacket) {
				t.Errorf("packet data = %x, want %x", data, testPacket)
			}

			want := time.Unix(1000, 0).Add(tt.wantFrac)
			if !ci.Timestamp.Equal(want) {
				t.Errorf("timestamp = %v, want %v", ci.Timestamp.UTC(), want.UTC())
			}

			if _, _, err = r.ReadPacketData(); err == nil {
				t.Error("expected an error after the last packet")
			}
		})
	}
}

// TestOpenPCAPCountsLegacyPackets guards the counting pass, which uses the
// zero copy path rather than ReadPacketData.
func TestOpenPCAPCountsLegacyPackets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.pcap")
	writeClassicPcap(t, path, binary.BigEndian, 2, 1, false, 1000, 0)

	count, err := countPackets(path)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}

	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
}

// TestOpenCapturePcapNG checks the other container still opens and reports a
// usable link type, which callers need to compile a BPF.
func TestOpenCapturePcapNG(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.pcapng")
	writePcapNG(t, path)

	format, err := DetectCaptureFormat(path)
	if err != nil {
		t.Fatal(err)
	}

	if format != CaptureFormatPCAPNG {
		t.Fatalf("format = %v, want PCAPNG", format)
	}

	isPcap, err := IsPcap(path)
	if err != nil {
		t.Fatal(err)
	}

	if isPcap {
		t.Error("IsPcap = true, want false for PCAPNG")
	}

	r, err := OpenCapture(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if r.LinkType() != layers.LinkTypeEthernet {
		t.Errorf("link type = %v, want Ethernet", r.LinkType())
	}

	data, _, err := r.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != string(testPacket) {
		t.Errorf("packet data = %x, want %x", data, testPacket)
	}
}

func TestOpenPCAPGzip(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.pcap")
	compressed := filepath.Join(dir, "compressed.pcap.gz")
	writeClassicPcap(t, plain, binary.LittleEndian, 2, 4, false, 1000, 0)

	contents, err := os.ReadFile(plain)
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(compressed)
	if err != nil {
		t.Fatal(err)
	}

	zw := gzip.NewWriter(f)
	if _, err = zw.Write(contents); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}

	format, err := DetectCaptureFormat(compressed)
	if err != nil {
		t.Fatal(err)
	}
	if format != CaptureFormatPCAP {
		t.Fatalf("format = %v, want PCAP", format)
	}

	r, err := OpenPCAPReader(compressed)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	data, _, err := r.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(testPacket) {
		t.Errorf("packet data = %x, want %x", data, testPacket)
	}
}

// TestOpenPCAPRejectsDamagedFiles checks that a file carrying PCAP magic is
// reported as a PCAP problem and never retried as PCAPNG.
func TestOpenPCAPRejectsDamagedFiles(t *testing.T) {
	tests := []struct {
		name     string
		contents func(t *testing.T, path string)
	}{
		{
			name: "truncated file header",
			contents: func(t *testing.T, path string) {
				header := make([]byte, 12)
				binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4)
				if err := os.WriteFile(path, header, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "truncated packet record",
			contents: func(t *testing.T, path string) {
				header := make([]byte, 24)
				binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4)
				binary.LittleEndian.PutUint16(header[4:6], 2)
				binary.LittleEndian.PutUint16(header[6:8], 4)
				binary.LittleEndian.PutUint32(header[16:20], 262144)
				binary.LittleEndian.PutUint32(header[20:24], uint32(layers.LinkTypeEthernet))

				record := make([]byte, 16)
				binary.LittleEndian.PutUint32(record[8:12], 100)
				binary.LittleEndian.PutUint32(record[12:16], 100)

				if err := os.WriteFile(path, append(header, record...), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "damaged.pcap")
			tt.contents(t, path)

			// The magic still identifies the container, so the file must stay
			// a PCAP file rather than being handed to the PCAPNG reader.
			format, err := DetectCaptureFormat(path)
			if err != nil {
				t.Fatal(err)
			}

			if format != CaptureFormatPCAP {
				t.Fatalf("format = %v, want PCAP", format)
			}

			r, err := OpenPCAPReader(path)
			if err != nil {
				if strings.Contains(err.Error(), "PCAPNG") {
					t.Errorf("PCAP error mentions PCAPNG: %v", err)
				}

				return
			}

			// Opening may succeed when only the packet record is damaged;
			// reading it must then fail.
			defer r.Close()

			if _, _, err = r.ReadPacketData(); err == nil {
				t.Error("expected reading a damaged packet record to fail")
			}
		})
	}
}

// TestDetectCaptureFormatRejectsOtherFiles checks that files which are not
// captures are reported as unknown rather than guessed at.
func TestDetectCaptureFormatRejectsOtherFiles(t *testing.T) {
	tests := []struct {
		name     string
		contents []byte
	}{
		{name: "empty", contents: []byte{}},
		{name: "shorter than a magic number", contents: []byte{0xa1, 0xb2}},
		{name: "zip", contents: []byte{0x50, 0x4b, 0x03, 0x04, 0x00}},
		{name: "text", contents: []byte("not a capture file at all")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "other.bin")
			if err := os.WriteFile(path, tt.contents, 0o644); err != nil {
				t.Fatal(err)
			}

			format, err := DetectCaptureFormat(path)
			if err != nil {
				t.Fatal(err)
			}

			if format != CaptureFormatUnknown {
				t.Errorf("format = %v, want unknown", format)
			}

			isPcap, err := IsPcap(path)
			if err != nil {
				t.Fatal(err)
			}

			if isPcap {
				t.Error("IsPcap = true, want false")
			}

			if _, err = OpenCapture(path); err == nil {
				t.Error("expected OpenCapture to fail")
			}
		})
	}
}

// TestDetectCaptureFormatMissingFile checks that a missing path is an error
// rather than an unknown format.
func TestDetectCaptureFormatMissingFile(t *testing.T) {
	if _, err := DetectCaptureFormat(filepath.Join(t.TempDir(), "absent.pcap")); err == nil {
		t.Error("expected an error for a missing file")
	}

	if _, err := IsPcap(filepath.Join(t.TempDir(), "absent.pcap")); err == nil {
		t.Error("expected an error for a missing file")
	}
}
