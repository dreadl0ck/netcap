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

package bgp

import (
	"bytes"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var bgpLog = zap.NewNop()

const serviceBGP = "BGP"

// BGP marker - 16 bytes of 0xFF
var bgpMarker = bytes.Repeat([]byte{0xFF}, 16)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_BGP,
	Name:        serviceBGP,
	Description: "Border Gateway Protocol (BGP) is the protocol for routing between autonomous systems",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		bgpLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"bgp",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// BGP messages start with 16 bytes of 0xFF marker
		return (len(server) >= 19 && bytes.HasPrefix(server, bgpMarker)) ||
			(len(client) >= 19 && bytes.HasPrefix(client, bgpMarker))
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return bgpLog.Sync()
	},
	Factory: &bgpReader{},
	Typ:     core.TCP, // BGP uses TCP port 179
}
