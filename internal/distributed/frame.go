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

// Package distributed implements netcap's agent → collector transport.
//
// Agents connect over TLS 1.3 with mutual authentication. Both sides use
// self-signed Ed25519 certificates and trust each other by pinning the SHA-256
// of the peer's public key (SPKI). The collector derives a client's identity,
// and therefore its output directory, from its allowlist entry, never from
// anything the client sends.
//
// After the handshake the connection carries frames:
//
//	[1 byte type][4 byte big-endian payload length][payload]
//
// The agent sends Hello once, then Batch frames. The collector answers each
// Batch with an Ack carrying its sequence number once the data is written,
// or with an Error frame and closes the connection.
package distributed

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

// ProtocolVersion is the wire protocol version sent in the agent hello.
const ProtocolVersion = 1

// Frame types.
const (
	FrameHello byte = 1 // agent → collector, types.AgentHello
	FrameBatch byte = 2 // agent → collector, types.Batch
	FrameAck   byte = 3 // collector → agent, 8 byte big-endian sequence number
	FrameError byte = 4 // collector → agent, UTF-8 reason
)

// DefaultMaxFrame bounds a frame payload. It is checked before allocating.
const DefaultMaxFrame = 4 << 20

const frameHeaderLen = 5

var (
	// ErrFrameTooLarge is returned for a frame whose declared length exceeds the limit.
	ErrFrameTooLarge = errors.New("frame too large")
	// ErrUnknownFrame is returned for an unknown frame type.
	ErrUnknownFrame = errors.New("unknown frame type")
)

func knownFrame(t byte) bool {
	return t >= FrameHello && t <= FrameError
}

// WriteFrame writes one frame in a single Write call.
func WriteFrame(w io.Writer, t byte, payload []byte) error {
	if !knownFrame(t) {
		return fmt.Errorf("%w: %d", ErrUnknownFrame, t)
	}
	if uint64(len(payload)) > math.MaxUint32 {
		return ErrFrameTooLarge
	}

	buf := make([]byte, frameHeaderLen+len(payload))
	buf[0] = t
	binary.BigEndian.PutUint32(buf[1:frameHeaderLen], uint32(len(payload)))
	copy(buf[frameHeaderLen:], payload)

	_, err := w.Write(buf)

	return err
}

// ReadFrame reads one frame. A declared length above maxPayload fails
// with ErrFrameTooLarge before any payload memory is allocated.
func ReadFrame(r io.Reader, maxPayload int) (t byte, payload []byte, err error) {
	var hdr [frameHeaderLen]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}

	t = hdr[0]
	if !knownFrame(t) {
		return 0, nil, fmt.Errorf("%w: %d", ErrUnknownFrame, t)
	}

	n := binary.BigEndian.Uint32(hdr[1:])
	if uint64(n) > uint64(maxPayload) {
		return 0, nil, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, n, maxPayload)
	}

	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}

		return 0, nil, err
	}

	return t, payload, nil
}

// EncodeAck encodes an ack payload.
func EncodeAck(seq uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, seq)
}

// DecodeAck decodes an ack payload.
func DecodeAck(p []byte) (uint64, error) {
	if len(p) != 8 {
		return 0, fmt.Errorf("ack payload is %d bytes, want 8", len(p))
	}

	return binary.BigEndian.Uint64(p), nil
}

// CountRecords checks that data is a sequence of complete length-delimited
// records, each a valid protobuf of the record type for t, and returns how
// many there are. The collector refuses to write anything that fails this,
// so a malformed batch can never corrupt an output file.
func CountRecords(t types.Type, data []byte) (int, error) {
	n := 0
	for len(data) > 0 {
		size, k := binary.Uvarint(data)
		if k <= 0 {
			return n, fmt.Errorf("record %d: bad length prefix", n)
		}
		data = data[k:]
		if size > uint64(len(data)) {
			return n, fmt.Errorf("record %d: length %d exceeds remaining %d bytes", n, size, len(data))
		}

		rec := netio.InitRecord(t)
		if rec == nil {
			return n, fmt.Errorf("unknown record type %d", t)
		}
		if err := proto.Unmarshal(data[:size], rec); err != nil {
			return n, fmt.Errorf("record %d: %w", n, err)
		}

		data = data[size:]
		n++
	}

	return n, nil
}
