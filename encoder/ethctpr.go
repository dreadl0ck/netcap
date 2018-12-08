/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package encoder

import (
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var EthernetCTPReplyEncoder = CreateLayerEncoder(types.Type_NC_EthernetCTPReply, layers.LayerTypeEthernetCTPReply, func(layer gopacket.Layer, timestamp string) proto.Message {
	if ethctpr, ok := layer.(*layers.EthernetCTPReply); ok {
		return &types.EthernetCTPReply{
			Timestamp:     timestamp,
			Function:      int32(ethctpr.Function),
			ReceiptNumber: int32(ethctpr.ReceiptNumber),
			Data:          ethctpr.Data,
		}
	}
	return nil
})
