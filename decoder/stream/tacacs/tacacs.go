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

package tacacs

import (
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var tacacsLog = zap.NewNop()

const serviceTACACS = "TACACS"

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_TACACS,
	Name:        serviceTACACS,
	Description: "TACACS+ is a protocol for remote authentication and access control via a centralized server",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		tacacsLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"tacacs",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// TACACS+ major version is 0xC (top nibble)
		if len(client) >= 12 && client[0]&0xF0 == 0xC0 {
			return true
		}
		if len(server) >= 12 && server[0]&0xF0 == 0xC0 {
			return true
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return tacacsLog.Sync()
	},
	Factory: &tacacsReader{},
	Typ:     core.TCP,
}
