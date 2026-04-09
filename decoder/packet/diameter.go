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

// Diameter decoder disabled - requires custom gopacket fork with industrial protocol support
// The official gopacket/gopacket library does not include Diameter layer support

/*
import (
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

var diameterDecoder = newGoPacketDecoder(
	types.Type_NC_Diameter,
	layers.LayerTypeDiameter,
	"Diameter is an authentication, authorization, and accounting protocol for computer networks, it evolved from the earlier RADIUS protocol",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if d, ok := layer.(*layers.Diameter); ok {
			avps := make([]*types.AVP, 0, len(d.AVPs))
			for _, a := range d.AVPs {
				avps = append(avps, &types.AVP{
					AttributeCode:   a.AttributeCode,
					AttributeName:   a.AttributeName,
					AttributeFormat: a.AttributeFormat,
					Flags:           uint32(a.Flags),
					HeaderLen:       uint32(a.HeaderLen),
					Len:             a.Len,
					VendorCode:      a.VendorCode,
					VendorName:      a.VendorName,
					VendorID:        a.VendorID,
					DecodedValue:    a.DecodedValue,
					Padding:         a.Padding,
					Value:           a.Value,
					ValueLen:        a.ValueLen,
				})
			}

			return &types.Diameter{
				Timestamp:     timestamp,
				Version:       uint32(d.Version),
				Flags:         uint32(d.Flags),
				MessageLen:    d.MessageLen,
				CommandCode:   d.CommandCode,
				ApplicationID: d.ApplicationID,
				HopByHopID:    d.HopByHopID,
				EndToEndID:    d.EndToEndID,
				AVPs:          avps,
			}
		}

		return nil
	},
)
*/
