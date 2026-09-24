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

package kerberosaudit

import (
	"encoding/hex"
	"testing"
)

// udpMessage builds an ASN.1 application-tagged message with a definite DER
// length, as Kerberos sends over UDP.
func udpMessage(tag byte, bodyLen int) []byte {
	msg := []byte{tag}

	switch {
	case bodyLen < 0x80:
		msg = append(msg, byte(bodyLen))
	case bodyLen < 0x100:
		msg = append(msg, 0x81, byte(bodyLen))
	default:
		msg = append(msg, 0x82, byte(bodyLen>>8), byte(bodyLen))
	}

	return append(msg, make([]byte, bodyLen)...)
}

// tcpMessage prefixes a UDP-shaped message with the 4-byte record mark.
func tcpMessage(tag byte, bodyLen int) []byte {
	body := udpMessage(tag, bodyLen)
	mark := len(body)

	return append([]byte{byte(mark >> 24), byte(mark >> 16), byte(mark >> 8), byte(mark)}, body...)
}

func TestCanDecodeKerberos(t *testing.T) {
	for _, tag := range []byte{0x6a, 0x6b, 0x6c, 0x6d, 0x7e} {
		if !Decoder.CanDecode(udpMessage(tag, 64), nil) {
			t.Errorf("tag %#02x: UDP message rejected", tag)
		}
		if !Decoder.CanDecode(tcpMessage(tag, 300), nil) {
			t.Errorf("tag %#02x: TCP message rejected", tag)
		}
		if !Decoder.CanDecode(nil, udpMessage(tag, 64)) {
			t.Errorf("tag %#02x: server-side message rejected", tag)
		}
	}
}

func TestRejectsNonKerberos(t *testing.T) {
	for _, tt := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"one byte", []byte{0x6a}},
		{"tag with zero length", []byte{0x6a, 0x00}},
		{"tag with length past the data", []byte{0x6a, 0x7f, 0x00, 0x00}},
		{"unknown tag", udpMessage(0x30, 64)},
		{"indefinite length is not DER", []byte{0x6a, 0x80, 0x00, 0x00, 0x00, 0x00}},
		{"http", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if Decoder.CanDecode(tt.data, nil) {
				t.Error("accepted")
			}
		})
	}
}

// The record mark must be checked before the byte at offset 4 is trusted, or
// the mark's own bytes are read as a tag.
func TestRecordMarkMustAgree(t *testing.T) {
	msg := tcpMessage(0x6a, 300)

	// A mark far larger than the data present.
	tooBig := make([]byte, len(msg))
	copy(tooBig, msg)
	tooBig[0], tooBig[1] = 0x05, 0x64

	if Decoder.CanDecode(tooBig, nil) {
		t.Error("accepted a record mark larger than the stream")
	}

	zero := make([]byte, len(msg))
	copy(zero, msg)
	zero[0], zero[1], zero[2], zero[3] = 0, 0, 0, 0

	if Decoder.CanDecode(zero, nil) {
		t.Error("accepted a zero record mark")
	}
}

// A DNP3 frame's byte 4 is the outstation's destination address low byte. With
// no length check, any outstation numbered 106-109 or 126 was claimed as
// Kerberos -- and this decoder is reached before DNP3's in the fallback scan.
func TestDNP3IsNotKerberos(t *testing.T) {
	// A real select frame from tests/ICS-pcap/DNP3/DNP3-SelectOperate.
	frame, err := hex.DecodeString("05641ac403000400c9b7c1c1030c0128010001000301640000007b5e6400000000005b")
	if err != nil {
		t.Fatal(err)
	}

	for _, addr := range []byte{0x6a, 0x6b, 0x6c, 0x6d, 0x7e} {
		stream := make([]byte, 0, len(frame)*4)
		for range 4 {
			stream = append(stream, frame...)
		}

		stream[4] = addr // destination address low byte

		if Decoder.CanDecode(stream, nil) {
			t.Errorf("outstation address low byte %#02x: DNP3 claimed as Kerberos", addr)
		}
		if Decoder.CanDecode(nil, stream) {
			t.Errorf("outstation address low byte %#02x: DNP3 claimed as Kerberos (server side)", addr)
		}
	}
}

// Modbus MBAP opens with an arbitrary 16-bit transaction id, which lands on
// byte 0 and so was read as a tag.
func TestModbusIsNotKerberos(t *testing.T) {
	for _, hi := range []byte{0x6a, 0x6b, 0x6c, 0x6d, 0x7e} {
		// txid, protocol id 0, length, unit, function code, payload.
		adu := []byte{hi, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A}
		if Decoder.CanDecode(adu, nil) {
			t.Errorf("transaction id high byte %#02x: Modbus claimed as Kerberos", hi)
		}
	}
}

func TestDERMessageSize(t *testing.T) {
	for _, tt := range []struct {
		name string
		b    []byte
		size int
		ok   bool
	}{
		{"short form", append([]byte{0x6a, 0x05}, make([]byte, 5)...), 7, true},
		{"short form past the end", []byte{0x6a, 0x27, 0x00, 0x00}, 0, false},
		{"short form zero length", []byte{0x6a, 0x00}, 2, false},
		{"long form one octet", append([]byte{0x6a, 0x81, 0x40}, make([]byte, 64)...), 67, true},
		{"long form two octets", append([]byte{0x6a, 0x82, 0x01, 0x2C}, make([]byte, 300)...), 304, true},
		{"long form overruns", []byte{0x6a, 0x81, 0xFF, 0x00}, 0, false},
		{"indefinite rejected", []byte{0x6a, 0x80, 0x00, 0x00}, 0, false},
		{"more than four length octets", append([]byte{0x6a, 0x85}, make([]byte, 100)...), 0, false},
		{"too short", []byte{0x6a}, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			size, ok := derMessageSize(tt.b)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && size != tt.size {
				t.Errorf("size = %d, want %d", size, tt.size)
			}
		})
	}
}

// A message whose declared length merely fits inside the buffer is not enough:
// it has to account for it. This is the Modbus false positive in miniature.
func TestDERMessageMustAccountForTheBuffer(t *testing.T) {
	// A 1-octet body inside a 64-byte buffer.
	b := make([]byte, 64)
	b[0], b[1], b[2] = 0x6a, 0x01, 0x00

	if derMessageFits(b, len(b)) {
		t.Error("accepted a 1-octet body as a 64-byte message")
	}
}

// A declared length running past the buffer must not be returned as a size:
// the caller indexes with it. Caught by the collector suite as a panic.
func TestDeclaredLengthPastBufferIsRejected(t *testing.T) {
	// 39-octet body declared inside a 36-byte buffer.
	b := make([]byte, 36)
	b[0], b[1] = 0x6a, 0x27

	if derMessageFits(b, len(b)) {
		t.Error("accepted a message longer than the data")
	}
	if Decoder.CanDecode(b, nil) {
		t.Error("CanDecode accepted it")
	}
}

// Several concatenated messages are what a TCP direction looks like.
func TestChainedMessagesAccepted(t *testing.T) {
	stream := append(udpMessage(0x6a, 64), udpMessage(0x6b, 64)...)

	if !derMessageFits(stream, len(stream)) {
		t.Error("rejected two concatenated Kerberos messages")
	}
}
