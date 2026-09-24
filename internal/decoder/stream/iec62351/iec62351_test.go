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

	"github.com/dreadl0ck/netcap/internal/decoder/core"
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

// saFrame builds a DNP3 frame carrying a group 120 object, with correct block
// CRCs, so the reader has to strip them the way a device's frame requires.
func saFrame(t *testing.T, function, variation byte) []byte {
	t.Helper()

	// transport, application control, function code, group 120, variation,
	// qualifier, then object content.
	user := []byte{0xC1, 0xC1, function, dnp3SAObjectGroup, variation, 0x5B}
	user = append(user, make([]byte, 14)...)

	return frameFromUserData(t, user)
}

// frameFromUserData wraps application bytes in a link header and per-block
// CRCs, so every frame a test builds is one a device would accept.
func frameFromUserData(t *testing.T, user []byte) []byte {
	t.Helper()

	frame := []byte{0x05, 0x64, byte(len(user) + 5), 0xC4, 0x03, 0x00, 0x04, 0x00}
	frame = append(frame, crcLE(crc16DNP(frame))...)

	// One data block: up to 16 octets followed by their CRC.
	for off := 0; off < len(user); off += 16 {
		end := min(off+16, len(user))
		frame = append(frame, user[off:end]...)
		frame = append(frame, crcLE(crc16DNP(user[off:end]))...)
	}

	return frame
}

func crcLE(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }

// crc16DNP is CRC-16/DNP, restated here so the test builds frames a device
// would accept rather than frames the decoder happens to tolerate.
func crc16DNP(b []byte) uint16 {
	var crc uint16

	for _, v := range b {
		crc ^= uint16(v)

		for range 8 {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xA6BC
			} else {
				crc >>= 1
			}
		}
	}

	return ^crc
}

// The reader must read the variation from the object header's real position.
// It used to scan for any byte equal to 0x78 from offset 10, which finds one in
// an address, a block CRC or a measurement just as readily.
func TestReaderFindsSecureAuthenticationObject(t *testing.T) {
	for variation, name := range map[byte]string{
		1: "AuthenticationChallenge",
		2: "AuthenticationReply",
		3: "AggressiveModeRequest",
		7: "AuthenticationError",
	} {
		frame := saFrame(t, dnp3AuthenticateReq, variation)

		r := &iec62351Reader{conversation: &core.ConversationInfo{}}

		msg, consumed := r.parseDNP3SAMessage(frame)
		if msg == nil {
			t.Fatalf("variation %d: no record", variation)
		}

		if consumed != len(frame) {
			t.Errorf("variation %d: consumed %d of %d bytes; the frame length must include the block CRCs",
				variation, consumed, len(frame))
		}

		if !msg.IsAuthenticationEvent {
			t.Errorf("variation %d: not flagged as an authentication event", variation)
		}

		if msg.MessageType != int32(variation) || msg.MessageTypeName != name {
			t.Errorf("variation %d: decoded as %d %q, want %q", variation, msg.MessageType, msg.MessageTypeName, name)
		}
	}
}

// A 0x78 in the payload is not an object header. The frame is rebuilt so its
// block CRCs are correct, or the reader would refuse it for that reason instead
// and the test would pass without proving anything.
func TestReaderIgnoresStrayObjectGroupByte(t *testing.T) {
	// Object group 1, not 120, and a stray 0x78 further into the payload where
	// the old byte scan would have found it.
	user := []byte{0xC1, 0xC1, dnp3AuthenticateReq, 0x01, 0x02, 0x5B, 0x00, 0x00, 0x78, 0x01}
	user = append(user, make([]byte, 10)...)

	frame := frameFromUserData(t, user)

	r := &iec62351Reader{conversation: &core.ConversationInfo{}}

	msg, consumed := r.parseDNP3SAMessage(frame)
	if msg == nil {
		t.Fatal("no record")
	}

	if consumed != len(frame) {
		t.Fatalf("consumed %d of %d bytes: the frame is malformed, so this test proves nothing",
			consumed, len(frame))
	}

	if msg.IsAuthenticationEvent {
		t.Errorf("a stray 0x78 was read as a group 120 object header, giving variation %d", msg.MessageType)
	}
}
