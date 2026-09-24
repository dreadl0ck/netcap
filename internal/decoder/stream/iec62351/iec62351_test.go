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

package iec62351

import (
	"encoding/hex"
	"testing"
)

// dnp3Frame builds a DNP3 frame carrying an application function code.
// Layout: start(2) length control dest(2) source(2) crc(2) | transport
// app-control function ...
func dnp3Frame(function byte, trailing ...byte) []byte {
	frame := []byte{
		0x05, 0x64, // start
		0x1A,       // length
		0xC4,       // control
		0x03, 0x00, // destination
		0x04, 0x00, // source
		0xC9, 0xB7, // header CRC
		0xC1,     // transport
		0xC1,     // application control
		function, // application function code
	}

	return append(frame, trailing...)
}

// The three Secure Authentication v5 function codes are what this decoder
// legitimately claims.
func TestClaimsSecureAuthentication(t *testing.T) {
	for _, fn := range []byte{dnp3AuthenticateReq, dnp3AuthenticateReqNoAck, dnp3AuthenticateResp} {
		frame := dnp3Frame(fn, make([]byte, 20)...)

		if !hasDNP3SecureAuth(frame) {
			t.Errorf("function %#02x: Secure Authentication message rejected", fn)
		}
		if !Decoder.CanDecode(frame, nil) {
			t.Errorf("function %#02x: CanDecode rejected it", fn)
		}
	}
}

// Ordinary telemetry belongs to the DNP3 decoder. This one sits at port 2404
// and DNP3 at 20000, so claiming it here means DNP3 never gets asked.
func TestDoesNotClaimPlainDNP3(t *testing.T) {
	for _, tt := range []struct {
		name string
		fn   byte
	}{
		{"read", 0x01},
		{"write", 0x02},
		{"select", 0x03},
		{"operate", 0x04},
		{"direct operate", 0x05},
		{"cold restart", 0x0D},
		{"response", 0x81},
		{"unsolicited response", 0x82},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Trailing bytes deliberately include 0x78, object group 120: the
			// old check scanned for that byte anywhere from offset 11 and so
			// matched essentially every DNP3 conversation.
			frame := dnp3Frame(tt.fn, 0x0C, 0x01, 0x28, 0x78, 0x00, 0x01, 0x00, 0x78, 0x64, 0x00)

			if hasDNP3SecureAuth(frame) {
				t.Error("plain DNP3 claimed as Secure Authentication")
			}
		})
	}
}

// The real select frame from the capture corpus, which the old check claimed.
func TestDoesNotClaimCapturedDNP3(t *testing.T) {
	frame, err := hex.DecodeString("05641ac403000400c9b7c1c1030c0128010001000301640000007b5e6400000000005b")
	if err != nil {
		t.Fatal(err)
	}

	if hasDNP3SecureAuth(frame) {
		t.Error("a captured DNP3 select frame was claimed as Secure Authentication")
	}
}

func TestRejectsShortAndNonDNP3(t *testing.T) {
	for _, tt := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"start bytes only", []byte{0x05, 0x64}},
		{"truncated before the function code", dnp3Frame(dnp3AuthenticateReq)[:12]},
		{"wrong start bytes", append([]byte{0x06, 0x64}, make([]byte, 20)...)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if hasDNP3SecureAuth(tt.data) {
				t.Error("accepted")
			}
		})
	}
}
