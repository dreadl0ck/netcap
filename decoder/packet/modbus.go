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

package packet

// Modbus decoder disabled - requires custom gopacket fork with industrial protocol support
// The official gopacket/gopacket library does not include Modbus layer support

/*
import (
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

var modbusDecoder = newGoPacketDecoder(
	types.Type_NC_Modbus,
	layers.LayerTypeModbus,
	"Modbus is a data communications protocol originally published by Modicon in 1979 for use with its programmable logic controllers",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if m, ok := layer.(*layers.Modbus); ok {
			var payload []byte
			if conf.IncludePayloads {
				payload = m.ReqResp
			}

			return &types.Modbus{
				Timestamp:     timestamp,
				TransactionID: int32(m.TransactionID),
				ProtocolID:    int32(m.ProtocolID),
				Length:        int32(m.Length),
				UnitID:        int32(m.UnitID),
				Payload:       payload,
				Exception:     m.Exception,
				FunctionCode:  int32(m.FunctionCode),
			}
		}

		return nil
	},
)
*/
