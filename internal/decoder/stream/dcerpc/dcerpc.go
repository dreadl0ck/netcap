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

package dcerpc

import (
	"encoding/binary"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var dcerpcLog = zap.NewNop()

const serviceDCERPC = "DCERPC"

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_DCERPC,
	Name:        serviceDCERPC,
	Description: "DCE/RPC is the remote procedure call system used by Windows for DCOM and Active Directory services",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		dcerpcLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"dcerpc",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	// The common header must include a valid representation and fragment length.
	Specificity: core.SpecificityWeak,

	CanDecode: func(client, server []byte) bool {
		return isDCERPC(client) || isDCERPC(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return dcerpcLog.Sync()
	},
	Factory: &dcerpcReader{},
	Typ:     core.TCP,
}

// isDCERPC checks for a DCE/RPC v5 header.
func isDCERPC(data []byte) bool {
	if len(data) < 16 {
		return false
	}

	// Version must be 5
	if data[0] != 5 {
		return false
	}

	// Minor version 0 or 1
	if data[1] != 0 && data[1] != 1 {
		return false
	}

	// Packet type must be 0-19
	if data[2] > 19 {
		return false
	}
	if (data[4] != 0 && data[4] != 0x10) || data[5] != 0 || data[6] != 0 || data[7] != 0 {
		return false
	}
	var order binary.ByteOrder = binary.BigEndian
	if data[4] == 0x10 {
		order = binary.LittleEndian
	}
	length, auth := int(order.Uint16(data[8:10])), int(order.Uint16(data[10:12]))
	if length < 16 || auth > length-16 || auth > 0 && auth+24 > length {
		return false
	}

	return true
}
