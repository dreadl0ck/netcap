/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package packet

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

var diameterDecoder = newGoPacketDecoder(
	types.Type_NC_Diameter,
	layers.LayerTypeDiameter,
	"Diameter is an authentication, authorization, and accounting protocol for computer networks, it evolved from the earlier RADIUS protocol",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if d, ok := layer.(*layers.Diameter); ok {
			var avps []*types.AVP
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
