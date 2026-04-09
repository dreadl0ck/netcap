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

var bfdDecoder = newGoPacketDecoder(
	types.Type_NC_BFD,
	layers.LayerTypeBFD,
	"Bidirectional Forwarding Detection (BFD) is a network protocol that is used to detect faults between two forwarding engines connected by a link",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if bfd, ok := layer.(*layers.BFD); ok {
			var authHeader *types.BFDAuthHeader
			if bfd.AuthHeader != nil {
				authHeader = &types.BFDAuthHeader{
					AuthType:       int32(bfd.AuthHeader.AuthType),
					KeyID:          int32(bfd.AuthHeader.KeyID),
					SequenceNumber: int32(bfd.AuthHeader.SequenceNumber),
					Data:           bfd.AuthHeader.Data,
				}
			}

			return &types.BFD{
				Timestamp:                 timestamp,
				Version:                   int32(bfd.Version),
				Diagnostic:                int32(bfd.Diagnostic),
				State:                     int32(bfd.State),
				Poll:                      bfd.Poll,
				Final:                     bfd.Final,
				ControlPlaneIndependent:   bfd.ControlPlaneIndependent,
				AuthPresent:               bfd.AuthPresent,
				Demand:                    bfd.Demand,
				Multipoint:                bfd.Multipoint,
				DetectMultiplier:          int32(bfd.DetectMultiplier),
				MyDiscriminator:           int32(bfd.MyDiscriminator),
				YourDiscriminator:         int32(bfd.YourDiscriminator),
				DesiredMinTxInterval:      int32(bfd.DesiredMinTxInterval),
				RequiredMinRxInterval:     int32(bfd.RequiredMinRxInterval),
				RequiredMinEchoRxInterval: int32(bfd.RequiredMinEchoRxInterval),
				AuthHeader:                authHeader,
			}
		}

		return nil
	},
)
