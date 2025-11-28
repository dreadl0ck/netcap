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

package socks

import (
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var socksLog = zap.NewNop()

const serviceSOCKS = "SOCKS"

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_SOCKS,
	Name:        serviceSOCKS,
	Description: "SOCKS is a proxy protocol for routing packets between client and server through a proxy",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		socksLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"socks",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// SOCKS5 handshake starts with version byte (0x05) and number of auth methods
		if len(client) >= 3 && client[0] == 0x05 && int(client[1])+2 <= len(client) {
			return true
		}
		// SOCKS4 request starts with version byte (0x04) and command byte
		if len(client) >= 9 && client[0] == 0x04 && (client[1] == 0x01 || client[1] == 0x02) {
			return true
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return socksLog.Sync()
	},
	Factory: &socksReader{},
	Typ:     core.TCP, // SOCKS uses TCP port 1080
}
