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

package rdp

import (
	"bytes"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
)

var rdpLog = zap.NewNop()

const serviceRDP = "RDP"

// TPKT header byte
const tpktVersion = 0x03

// X.224 Connection Request code
const x224ConnectionRequest = 0xE0
const x224ConnectionConfirm = 0xD0

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_RDP,
	Name:        serviceRDP,
	Description: "Remote Desktop Protocol (RDP) is Microsoft's remote access protocol",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		rdpLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"rdp",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// RDP uses TPKT (starts with 0x03) over TCP
		// Client sends X.224 Connection Request (0xE0)
		// Server responds with X.224 Connection Confirm (0xD0)
		if len(client) >= 11 && client[0] == tpktVersion {
			// Check for X.224 Connection Request
			if client[5] == x224ConnectionRequest {
				return true
			}
			// Check for RDP Cookie pattern "Cookie: mstshash="
			if bytes.Contains(client, []byte("Cookie:")) && bytes.Contains(client, []byte("mstshash=")) {
				return true
			}
		}
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return rdpLog.Sync()
	},
	Factory: &rdpReader{},
	Typ:     core.TCP, // RDP uses TCP port 3389
}
