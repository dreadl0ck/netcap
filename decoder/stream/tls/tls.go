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

package tls

import (
	"github.com/dreadl0ck/netcap/decoder/core"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var tlsLog = zap.NewNop()

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TLS handshake constants
const (
	// TLS Record Layer Content Types
	recordTypeHandshake = 0x16

	// TLS Handshake Message Types
	handshakeTypeClientHello = 0x01
	handshakeTypeServerHello = 0x02
	handshakeTypeCertificate = 0x0b
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_TLSCertificate,
	Name:        serviceTLS,
	Description: "Transport Layer Security certificates extracted from TLS handshakes",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		tlsLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"tls",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// Check for TLS handshake in client data (ClientHello)
		if len(client) >= 6 {
			// TLS record: [ContentType(1)][Version(2)][Length(2)][HandshakeType(1)]
			if client[0] == recordTypeHandshake &&
				(client[1] == 0x03 && client[2] <= 0x04) { // TLS versions 1.0-1.3
				if len(client) >= 6 && client[5] == handshakeTypeClientHello {
					tlsLog.Info("TLS traffic detected - CanDecode matched (ClientHello)",
						zap.Int("clientLen", len(client)),
						zap.Int("serverLen", len(server)),
					)
					return true
				}
			}
		}

		// Check for TLS handshake in server data (ServerHello)
		if len(server) >= 6 {
			if server[0] == recordTypeHandshake &&
				(server[1] == 0x03 && server[2] <= 0x04) {
				if len(server) >= 6 && server[5] == handshakeTypeServerHello {
					tlsLog.Info("TLS traffic detected - CanDecode matched (ServerHello)",
						zap.Int("clientLen", len(client)),
						zap.Int("serverLen", len(server)),
					)
					return true
				}
			}
		}

		tlsLog.Debug("TLS CanDecode check failed",
			zap.Int("clientLen", len(client)),
			zap.Int("serverLen", len(server)),
		)
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		// Flush all certificates before shutdown
		err := flushCertificates(sd)
		if err != nil {
			tlsLog.Error("Failed to flush certificates", zap.Error(err))
		}
		return tlsLog.Sync()
	},
	Factory: &tlsReader{},
	Typ:     core.TCP,
}

var (
	serviceTLS = "TLSCertificate"
)

// isTLSHandshake checks if the data starts with a TLS handshake record
func isTLSHandshake(data []byte) bool {
	if len(data) < 6 {
		return false
	}

	// Check for TLS record header
	// Byte 0: Content Type (0x16 = Handshake)
	// Bytes 1-2: TLS Version (0x03, 0x00-0x04 for TLS 1.0-1.3)
	// Bytes 3-4: Length
	// Byte 5: Handshake Type
	return data[0] == recordTypeHandshake &&
		data[1] == 0x03 &&
		data[2] <= 0x04
}
