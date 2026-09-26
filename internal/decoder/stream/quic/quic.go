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

package quic

import (
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var quicLog = zap.NewNop()

const serviceQUIC = "QUICClientHello"

// Minimum packet size for QUIC Initial packets (padding requirement)
const minQUICInitialSize = 1200

// Decoder for QUIC protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_QUICClientHello,
	Name:        serviceQUIC,
	Description: "QUIC ClientHello extraction for JA4 fingerprinting (supports IETF QUIC and gQUIC)",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		quicLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"quic",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	// Varies with the data: a long header naming a known version is five
	// validated bytes, while the short-header forms are a handful of bit tests.
	Specificity: core.SpecificityHeuristic,
	Confidence:  quicConfidence,
	// A short header alone is a few bit tests and cannot yield a ClientHello.
	// Only a versioned long header identifies an unknown UDP service.
	FallbackMinSpecificity: core.SpecificityStructural,

	CanDecode: func(client, server []byte) bool {
		// Check if client data looks like QUIC
		if len(client) >= 5 {
			// Check for IETF QUIC
			if IsIETFQUICPacket(client) {
				quicLog.Debug("QUIC traffic detected - IETF QUIC",
					zap.Int("clientLen", len(client)),
					zap.Int("serverLen", len(server)),
				)
				return true
			}

			// Check for gQUIC
			if IsGQUICPacket(client) {
				quicLog.Debug("QUIC traffic detected - gQUIC",
					zap.Int("clientLen", len(client)),
					zap.Int("serverLen", len(server)),
				)
				return true
			}
		}

		quicLog.Debug("QUIC CanDecode check failed",
			zap.Int("clientLen", len(client)),
			zap.Int("serverLen", len(server)),
		)
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return quicLog.Sync()
	},
	Factory: &quicReader{},
	Typ:     core.UDP, // QUIC uses UDP
}

// CanDecodeQUIC provides a public check for QUIC detection.
// This can be used by other parts of the system.
func CanDecodeQUIC(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	return IsIETFQUICPacket(data) || IsGQUICPacket(data)
}

// quicConfidence separates a validated QUIC header from the bit tests that
// stand in for one after the handshake.
//
// Both short-header paths are guesses. IsIETFQUICPacket falls back to a single
// bit, and IsGQUICPacket accepts any first byte with the connection-id bit set,
// the version bit clear and the top three bits clear. 0x0a satisfies all three,
// and 0x0a is the opening byte of almost every protobuf message -- field 1,
// wire type 2 -- so rating those paths above a structural check took the
// protobuf UDP corpus away from the protobuf decoder.
//
// A long header carrying a recognized version, or a gQUIC "Qxxx" version
// string, is a different quality of evidence and says so.
func quicConfidence(client, server []byte) int {
	for _, data := range [][]byte{client, server} {
		if hasValidatedQUICVersion(data) {
			return core.SpecificityStructural
		}
	}

	return core.SpecificityHeuristic
}

// hasValidatedQUICVersion reports whether data carries a version field that was
// checked against the known values, rather than a header shape.
func hasValidatedQUICVersion(data []byte) bool {
	if len(data) < 5 {
		return false
	}

	// IETF long header: form bit set, then a version this decoder recognizes.
	if data[0]&0x80 == 0x80 && IsIETFQUICPacket(data) {
		return true
	}

	// gQUIC carries its version as "Q" followed by three digits.
	for i := 1; i <= 9 && i+4 <= len(data); i++ {
		if data[i] == 'Q' && isDigit(data[i+1]) && isDigit(data[i+2]) && isDigit(data[i+3]) {
			return true
		}
	}

	return false
}
