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

package dnp3

import (
	"encoding/hex"
	"testing"
)

// The CRC-16/DNP catalogue check value, so a table or polynomial error fails
// here rather than showing up as unexplained frame loss.
func TestCRC16DNPCheckValue(t *testing.T) {
	if got := crc16DNP([]byte("123456789")); got != 0xEA82 {
		t.Fatalf("check value = %#04x, want 0xea82", got)
	}
}

// Header CRCs lifted from tests/ICS-pcap/DNP3. These are real frames, so a
// change that passes the catalogue vector but mis-handles live traffic fails.
func TestCRC16DNPHeaders(t *testing.T) {
	for _, tt := range []struct {
		name  string
		frame string
	}{
		{"select", "05641ac403000400c9b7"},
		{"operate", "05641ac403000400c9b7"},
		{"read", "05640bc403000400ef7a"},
		{"write", "056412c403000400152d"},
		{"request link status", "056405c903000400bd71"},
		{"malformed sender", "056402c40a00010097fe"},
		{"operate crob", "056419c40a000100da8f"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b, err := hex.DecodeString(tt.frame)
			if err != nil {
				t.Fatal(err)
			}
			if !crcValid(b[:linkHeaderLen-2], b[linkHeaderLen-2:linkHeaderLen]) {
				t.Errorf("header CRC rejected, want accepted (computed %#04x)", crc16DNP(b[:linkHeaderLen-2]))
			}
		})
	}
}

// A single flipped bit anywhere in the header must be rejected. Without this
// the scan re-admits the phantom frames the CRC exists to exclude.
func TestCRC16DNPRejectsCorruption(t *testing.T) {
	b, err := hex.DecodeString("05641ac403000400c9b7")
	if err != nil {
		t.Fatal(err)
	}
	for i := range linkHeaderLen - 2 {
		for bit := range 8 {
			corrupt := make([]byte, len(b))
			copy(corrupt, b)
			corrupt[i] ^= 1 << bit
			if crcValid(corrupt[:linkHeaderLen-2], corrupt[linkHeaderLen-2:linkHeaderLen]) {
				t.Errorf("byte %d bit %d: corruption accepted", i, bit)
			}
		}
	}
}

func TestCRCValidRejectsShortInput(t *testing.T) {
	if crcValid([]byte{0x05, 0x64}, []byte{0x00}) {
		t.Error("accepted a 1-byte CRC")
	}
}

// Block CRCs, which cover up to 16 bytes of user data each. The select frame
// carries 21 user octets, so it spans a full block and a partial one.
func TestCRC16DNPBlocks(t *testing.T) {
	b, err := hex.DecodeString("05641ac403000400c9b7c1c1030c0128010001000301640000007b5e6400000000005b")
	if err != nil {
		t.Fatal(err)
	}
	body := b[linkHeaderLen:]
	if !crcValid(body[:16], body[16:18]) {
		t.Errorf("first block CRC rejected (computed %#04x)", crc16DNP(body[:16]))
	}
	if !crcValid(body[18:23], body[23:25]) {
		t.Errorf("trailing block CRC rejected (computed %#04x)", crc16DNP(body[18:23]))
	}
}
