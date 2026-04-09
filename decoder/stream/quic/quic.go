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

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
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

