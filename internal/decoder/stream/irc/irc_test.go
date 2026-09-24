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

package irc

import (
	"encoding/hex"
	"testing"
)

func TestCanDecodeIRC(t *testing.T) {
	for _, tt := range []struct {
		name   string
		client []byte
		server []byte
		accept bool
	}{
		{
			"welcome numeric",
			nil,
			[]byte(":irc.example.net 001 nick :Welcome to the network\r\n"),
			true,
		},
		{
			"notice",
			nil,
			[]byte(":irc.example.net NOTICE AUTH :*** Looking up your hostname\r\n"),
			true,
		},
		{
			"numeric on a later line",
			nil,
			[]byte(":irc.example.net NOTICE AUTH :*** hi\r\n:irc.example.net 001 nick :Welcome\r\n"),
			true,
		},
		{
			"nick registration",
			[]byte("NICK nick\r\nUSER u 0 * :r\r\n"),
			[]byte(":irc.example.net 002 nick :Your host is\r\n"),
			true,
		},
		{"empty", nil, nil, false},
		{"plain text mentioning 001", nil, []byte("order 001 shipped\r\n"), false},
		{"numeric with no prefix", nil, []byte("001 nick :Welcome\r\n"), false},
		{"http", nil, []byte("HTTP/1.1 200 OK\r\nContent-Length: 001\r\n\r\n"), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decoder.CanDecode(tt.client, tt.server); got != tt.accept {
				t.Errorf("CanDecode = %v, want %v", got, tt.accept)
			}
		})
	}
}

// The bytes 0x30 0x30 0x31 occur in binary data constantly. Matching them as a
// bare substring let this decoder, at port 6667, claim any conversation
// belonging to a decoder above it.
func TestBinaryDataIsNotIRC(t *testing.T) {
	// A real DNP3 select frame repeated, from tests/ICS-pcap/DNP3.
	frame, err := hex.DecodeString("05641ac403000400c9b7c1c1030c0128010001000301640000007b5e6400000000005b")
	if err != nil {
		t.Fatal(err)
	}

	stream := make([]byte, 0, len(frame)*8)
	for range 8 {
		stream = append(stream, frame...)
	}

	if Decoder.CanDecode(nil, stream) {
		t.Error("claimed a DNP3 stream as IRC")
	}

	// The literal bytes, embedded in binary noise.
	noise := append([]byte{0x00, 0xFF, 0x7F}, []byte("001")...)
	noise = append(noise, 0x00, 0xFF)

	if Decoder.CanDecode(nil, noise) {
		t.Error("claimed binary noise containing \"001\" as IRC")
	}
}

func TestHasIRCReply(t *testing.T) {
	for _, tt := range []struct {
		name string
		data string
		want bool
	}{
		{"prefixed reply", ":srv 001 nick :hi\r\n", true},
		{"second line", "noise\n:srv 001 nick :hi\r\n", true},
		{"no prefix", "srv 001 nick :hi\r\n", false},
		{"prefix on another line", ":srv NOTICE x\r\nplain 001 text\r\n", false},
		{"substring only", "x001x", false},
		{"empty", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasIRCReply([]byte(tt.data), []byte(" 001 ")); got != tt.want {
				t.Errorf("hasIRCReply = %v, want %v", got, tt.want)
			}
		})
	}
}
