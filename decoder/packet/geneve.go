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

var geneveDecoder = newGoPacketDecoder(
	types.Type_NC_Geneve,
	layers.LayerTypeGeneve,
	"Geneve is a network virtualization overlay encapsulation protocol designed to establish tunnels between network virtualization end points (NVE) over an existing IP network",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if geneve, ok := layer.(*layers.Geneve); ok {
			var opts []*types.GeneveOption
			if len(geneve.Options) > 0 {
				for _, o := range geneve.Options {
					opts = append(opts, &types.GeneveOption{
						Class:  int32(o.Class),
						Type:   int32(o.Type),
						Flags:  int32(o.Flags),
						Length: int32(o.Length),
						Data:   o.Data,
					})
				}
			}

			return &types.Geneve{
				Timestamp:      timestamp,
				Version:        int32(geneve.Version),
				OptionsLength:  int32(geneve.OptionsLength),
				OAMPacket:      geneve.OAMPacket,
				CriticalOption: geneve.CriticalOption,
				Protocol:       int32(geneve.Protocol),
				VNI:            geneve.VNI,
				Options:        opts,
			}
		}

		return nil
	},
)
