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

var vrrpv2Decoder = newGoPacketDecoder(
	types.Type_NC_VRRPv2,
	layers.LayerTypeVRRP,
	"The Virtual Router Redundancy Protocol is a computer networking protocol that provides for automatic assignment of available Internet Protocol routers to participating hosts",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if vrrpv2, ok := layer.(*layers.VRRPv2); ok {
			var addr []string
			for _, a := range vrrpv2.IPAddress {
				addr = append(addr, a.String())
			}

			return &types.VRRPv2{
				Timestamp:    timestamp,
				Version:      int32(vrrpv2.Version),
				Type:         int32(vrrpv2.Type),
				VirtualRtrID: int32(vrrpv2.VirtualRtrID),
				Priority:     int32(vrrpv2.Priority),
				CountIPAddr:  int32(vrrpv2.CountIPAddr),
				AuthType:     int32(vrrpv2.AuthType),
				AdverInt:     int32(vrrpv2.AdverInt),
				Checksum:     int32(vrrpv2.Checksum),
				IPAddress:    addr,
			}
		}

		return nil
	},
)
