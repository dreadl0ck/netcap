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

package dnp3

import (
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var dnp3Log = zap.NewNop()

const serviceDNP3 = "DNP3"

// hasFrame reports whether b contains a link header whose CRC passes.
//
// The start bytes alone are a two-byte signature and match constantly inside
// binary payloads. Requiring the header CRC makes the claim a 16-bit check over
// 8 bytes instead, which is what allows the port-independent fallback scan to
// run without inventing conversations.
//
// The cost is that a capture beginning midstream, where no frame boundary falls
// inside the inspected bytes, is not claimed.
func hasFrame(b []byte) bool {
	for off := 0; off+linkHeaderLen <= len(b); {
		start := frameStart(b, off)
		if start < 0 || start+linkHeaderLen > len(b) {
			return false
		}

		header := b[start : start+linkHeaderLen]
		if crcValid(header[:linkHeaderLen-2], header[linkHeaderLen-2:]) {
			return true
		}

		off = start + 1
	}

	return false
}

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_DNP3,
	Name:        serviceDNP3,
	Description: "Distributed Network Protocol 3 (DNP3) is used for ICS/SCADA communications",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error

		dnp3Log, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"dnp3",
			decoderconfig.Instance.Debug,
		)

		return err
	},
	CanDecode: func(client, server []byte) bool {
		return hasFrame(client) || hasFrame(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return dnp3Log.Sync()
	},
	Factory: &dnp3Reader{},
	Typ:     core.TCP, // DNP3 uses TCP port 20000
}
