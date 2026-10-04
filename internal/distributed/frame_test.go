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

package distributed

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

func TestFrameRoundTrip(t *testing.T) {
	for _, ft := range []byte{FrameHello, FrameBatch, FrameAck, FrameError} {
		for _, p := range [][]byte{nil, {}, []byte("x"), bytes.Repeat([]byte{7}, 70000)} {
			var buf bytes.Buffer
			if err := WriteFrame(&buf, ft, p); err != nil {
				t.Fatal(err)
			}

			gt, gp, err := ReadFrame(&buf, DefaultMaxFrame)
			if err != nil || gt != ft || !bytes.Equal(gp, p) {
				t.Fatalf("type %d len %d: got %d len %d err %v", ft, len(p), gt, len(gp), err)
			}
		}
	}
}

func TestReadFrameRejectsBeforeAllocating(t *testing.T) {
	hdr := []byte{FrameBatch, 0xff, 0xff, 0xff, 0xff} // 4 GiB declared, no body
	if _, _, err := ReadFrame(bytes.NewReader(hdr), 1024); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v, want ErrFrameTooLarge", err)
	}
}

func TestReadFrameErrors(t *testing.T) {
	cases := map[string]struct {
		in   []byte
		want error
	}{
		"empty":            {nil, io.EOF},
		"short header":     {[]byte{FrameAck, 0, 0}, io.ErrUnexpectedEOF},
		"truncated body":   {[]byte{FrameAck, 0, 0, 0, 8, 1, 2}, io.ErrUnexpectedEOF},
		"missing body":     {[]byte{FrameAck, 0, 0, 0, 8}, io.ErrUnexpectedEOF},
		"unknown type 0":   {[]byte{0, 0, 0, 0, 0}, ErrUnknownFrame},
		"unknown type 255": {[]byte{255, 0, 0, 0, 0}, ErrUnknownFrame},
	}
	for name, tc := range cases {
		if _, _, err := ReadFrame(bytes.NewReader(tc.in), 1024); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}

	if err := WriteFrame(io.Discard, 9, nil); !errors.Is(err, ErrUnknownFrame) {
		t.Errorf("WriteFrame unknown type: %v", err)
	}
}

func TestAck(t *testing.T) {
	if got, err := DecodeAck(EncodeAck(1<<40 + 3)); err != nil || got != 1<<40+3 {
		t.Fatalf("got %d %v", got, err)
	}
	if _, err := DecodeAck([]byte{1, 2, 3}); err == nil {
		t.Fatal("short ack accepted")
	}
}

func delimitedTCP(t testing.TB, n int) []byte {
	t.Helper()

	var out []byte
	for i := 0; i < n; i++ {
		rec, err := proto.Marshal(&types.TCP{SrcPort: int32(i), SrcIP: "10.0.0.1", DstIP: "10.0.0.2"})
		if err != nil {
			t.Fatal(err)
		}
		out = binary.AppendUvarint(out, uint64(len(rec)))
		out = append(out, rec...)
	}

	return out
}

func TestCountRecords(t *testing.T) {
	good := delimitedTCP(t, 5)
	if n, err := CountRecords(types.Type_NC_TCP, good); err != nil || n != 5 {
		t.Fatalf("valid: %d %v", n, err)
	}
	if n, err := CountRecords(types.Type_NC_TCP, nil); err != nil || n != 0 {
		t.Fatalf("empty: %d %v", n, err)
	}

	bad := map[string][]byte{
		// v0.9.15 sent records without length prefixes.
		"undelimited":   good[1:],
		"truncated":     good[:len(good)-1],
		"bad varint":    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"overlong size": {0x80, 0x80, 0x80, 0x80, 0x10},
		"not a proto":   {3, 0xff, 0xff, 0xff},
	}
	for name, data := range bad {
		if _, err := CountRecords(types.Type_NC_TCP, data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	if _, err := CountRecords(types.Type(99999), good); err == nil {
		t.Error("unknown type accepted")
	}
}
