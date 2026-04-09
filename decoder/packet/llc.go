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

import (
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

var llcDecoder = newGoPacketDecoder(
	types.Type_NC_LLC,
	layers.LayerTypeLLC,
	"The LLC sublayer acts as an interface between the media access control sublayer and the network layer",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if llc, ok := layer.(*layers.LLC); ok {
			return &types.LLC{
				Timestamp: timestamp,
				DSAP:      int32(llc.DSAP),
				IG:        llc.IG,
				SSAP:      int32(llc.SSAP),
				CR:        llc.CR,
				Control:   int32(llc.Control),
			}
		}

		return nil
	},
)
