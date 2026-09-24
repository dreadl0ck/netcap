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

package socks

import (
	"encoding/hex"
	"testing"
)

// A real DNP3 select frame, from tests/ICS-pcap/DNP3/DNP3-SelectOperate.
// DNP3 frames begin 0x05 0x64, which is also the SOCKS5 version byte followed
// by a byte this decoder used to read as an authentication method count.
const dnp3Frame = "05641ac403000400c9b7c1c1030c0128010001000301640000007b5e6400000000005b"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func TestCanDecode(t *testing.T) {
	for _, tt := range []struct {
		name   string
		client []byte
		accept bool
	}{
		{"socks5 one method", []byte{0x05, 0x01, 0x00}, true},
		{"socks5 two methods", []byte{0x05, 0x02, 0x00, 0x02}, true},
		{"socks5 with request following", []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01}, true},
		{"socks4 connect", []byte{0x04, 0x01, 0x00, 0x50, 192, 0, 2, 1, 0x00}, true},
		{"socks4 bind", []byte{0x04, 0x02, 0x00, 0x50, 192, 0, 2, 1, 0x00}, true},

		// Zero methods is not a legal greeting; the old check accepted it.
		{"socks5 zero methods", []byte{0x05, 0x00, 0x00}, false},
		// 100 methods is not a greeting, it is a DNP3 start byte pair.
		{"socks5 absurd method count", append([]byte{0x05, 0x64}, make([]byte, 200)...), false},
		{"socks5 truncated methods", []byte{0x05, 0x04, 0x00}, false},
		{"empty", nil, false},
		{"too short", []byte{0x05}, false},
		{"socks4 wrong command", []byte{0x04, 0x09, 0x00, 0x50, 192, 0, 2, 1, 0x00}, false},
		{"http", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decoder.CanDecode(tt.client, nil); got != tt.accept {
				t.Errorf("CanDecode = %v, want %v", got, tt.accept)
			}
		})
	}
}

// The collision this decoder was tightened for. SOCKS sits at port 1080 and
// DNP3 at 20000, and the fallback scan runs in ascending port order, so a match
// here means DNP3 never reaches its own decoder.
func TestDNP3IsNotSOCKS(t *testing.T) {
	frame := mustHex(t, dnp3Frame)

	// One frame is below the old threshold; a real conversation is not.
	stream := make([]byte, 0, len(frame)*8)
	for range 8 {
		stream = append(stream, frame...)
	}

	if len(stream) < 102 {
		t.Fatalf("test stream is %d bytes, too short to exercise the old check", len(stream))
	}

	for _, tt := range []struct {
		name string
		data []byte
	}{
		{"single frame", frame},
		{"conversation", stream},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if Decoder.CanDecode(tt.data, nil) {
				t.Error("claimed a DNP3 stream as SOCKS")
			}
		})
	}
}

// The method count must be read as a count, not compared against however many
// bytes the direction happens to carry.
func TestMethodCountIsNotALengthComparison(t *testing.T) {
	// 20 methods declared, and plenty of trailing bytes to satisfy a naive
	// "count + 2 <= len" test.
	greeting := append([]byte{0x05, 20}, make([]byte, 500)...)

	if Decoder.CanDecode(greeting, nil) {
		t.Errorf("accepted a greeting declaring 20 methods; ceiling is %d", maxSocks5Methods)
	}
}
