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

package tacacs

import "testing"

// header builds a TACACS+ packet: version, type, seq, flags, session id,
// body length, body.
func header(version, pktType, seq byte, bodyLen int) []byte {
	h := []byte{
		version, pktType, seq, 0x00,
		0xDE, 0xAD, 0xBE, 0xEF,
		byte(bodyLen >> 24), byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen),
	}

	return append(h, make([]byte, bodyLen)...)
}

func TestAcceptsRealHeaders(t *testing.T) {
	for _, tt := range []struct {
		name    string
		version byte
		pktType byte
	}{
		{"authentication v12.0", 0xC0, tacacsTypeAuthentication},
		{"authorization v12.0", 0xC0, tacacsTypeAuthorization},
		{"accounting v12.0", 0xC0, tacacsTypeAccounting},
		{"minor version 1", 0xC1, tacacsTypeAuthentication},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pkt := header(tt.version, tt.pktType, 1, 40)

			if !Decoder.CanDecode(pkt, nil) {
				t.Error("rejected a valid header")
			}
			if !Decoder.CanDecode(nil, pkt) {
				t.Error("rejected a valid header on the server side")
			}
		})
	}
}

func TestRejectsMalformedHeaders(t *testing.T) {
	for _, tt := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"short of a header", header(0xC0, 1, 1, 0)[:11]},
		{"wrong major version", header(0xB0, 1, 1, 40)},
		{"minor version out of range", header(0xC5, 1, 1, 40)},
		{"unknown packet type", header(0xC0, 9, 1, 40)},
		{"sequence number zero", header(0xC0, 1, 0, 40)},
		{"zero body length", header(0xC0, 1, 1, 0)},
		{"absurd body length", append(header(0xC0, 1, 1, 0)[:8], 0x7F, 0xFF, 0xFF, 0xFF)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if Decoder.CanDecode(tt.data, nil) {
				t.Error("accepted")
			}
		})
	}
}

// The check used to be one nibble, which any binary conversation satisfies
// once in sixteen. TACACS+ sits at port 49, fourth in the port-independent
// scan, so it was taking that share of everything above it.
func TestModbusIsNotTACACS(t *testing.T) {
	stolen := 0

	for hi := range 256 {
		// MBAP: transaction id, protocol id 0, length 6, unit 1, FC3.
		adu := []byte{byte(hi), 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A}
		if Decoder.CanDecode(adu, nil) {
			stolen++
		}
	}

	if stolen > 0 {
		t.Errorf("claimed %d of 256 Modbus transaction ids as TACACS+", stolen)
	}
}

// Every first byte whose high nibble is 0xC used to match. Only a real header
// should now.
func TestArbitraryBinaryIsNotTACACS(t *testing.T) {
	for b := range 256 {
		data := make([]byte, 64)
		data[0] = byte(b)

		// Body length is zero in this buffer, so nothing should match.
		if Decoder.CanDecode(data, nil) {
			t.Errorf("first byte %#02x: accepted a zero-filled buffer", b)
		}
	}
}
