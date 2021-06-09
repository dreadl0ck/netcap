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
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

var arpDecoder = newGoPacketDecoder(
	types.Type_NC_ARP,
	layers.LayerTypeARP,
	"The Address Resolution Protocol resolves IP to hardware addresses",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if arp, ok := layer.(*layers.ARP); ok {
			return &types.ARP{
				Timestamp:           timestamp,
				AddrType:            int32(arp.AddrType),
				Protocol:            int32(arp.Protocol),
				HwAddressSize:       int32(arp.HwAddressSize),
				ProtocolAddressSize: int32(arp.ProtAddressSize),
				Operation:           int32(arp.Operation),
				SrcHwAddress:        formatMac(arp.SourceHwAddress),
				SrcProtocolAddress:  parseIPv4(arp.SourceProtAddress),
				DstHwAddress:        formatMac(arp.DstHwAddress),
				DstProtocolAddress:  parseIPv4(arp.DstProtAddress),
			}
		}

		return nil
	},
)
