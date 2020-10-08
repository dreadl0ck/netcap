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

var ethernetCTPReplyDecoder = newGoPacketDecoder(
	types.Type_NC_EthernetCTPReply,
	layers.LayerTypeEthernetCTPReply,
	"Ethernet Configuration Testing Protocol is a diagnostic protocol included in the Xerox Ethernet II specification",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if ethctpr, ok := layer.(*layers.EthernetCTPReply); ok {
			return &types.EthernetCTPReply{
				Timestamp:     timestamp,
				Function:      int32(ethctpr.Function),
				ReceiptNumber: int32(ethctpr.ReceiptNumber),
				Data:          ethctpr.Data,
			}
		}

		return nil
	},
)
