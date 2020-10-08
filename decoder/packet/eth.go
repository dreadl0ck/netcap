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

var ethernetDecoder = newGoPacketDecoder(
	types.Type_NC_Ethernet,
	layers.LayerTypeEthernet,
	"Ethernet is a family of computer networking technologies commonly used in local area networks, metropolitan area networks and wide area networks",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if eth, ok := layer.(*layers.Ethernet); ok {
			var e float64
			if conf.CalculateEntropy {
				e = entropy(eth.Payload)
			}

			return &types.Ethernet{
				Timestamp:      timestamp,
				SrcMAC:         eth.SrcMAC.String(),
				DstMAC:         eth.DstMAC.String(),
				EthernetType:   int32(eth.EthernetType),
				PayloadEntropy: e,
				PayloadSize:    int32(len(eth.Payload)),
			}
		}

		return nil
	},
)
