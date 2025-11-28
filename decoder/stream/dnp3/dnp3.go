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

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
)

var dnp3Log = zap.NewNop()

const serviceDNP3 = "DNP3"

// DNP3 start bytes
const (
	dnp3StartByte1 = 0x05
	dnp3StartByte2 = 0x64
)

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
		// DNP3 frames start with 0x05 0x64 (start bytes)
		return (len(client) >= 10 && client[0] == dnp3StartByte1 && client[1] == dnp3StartByte2) ||
			(len(server) >= 10 && server[0] == dnp3StartByte1 && server[1] == dnp3StartByte2)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return dnp3Log.Sync()
	},
	Factory: &dnp3Reader{},
	Typ:     core.TCP, // DNP3 uses TCP port 20000
}
