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

var dhcpv6Encoder = CreateLayerEncoder(types.Type_NC_DHCPv6, layers.LayerTypeDHCPv6, func(layer gopacket.Layer, timestamp string) proto.Message {
	if dhcp6, ok := layer.(*layers.DHCPv6); ok {

		var opts []*types.DHCPv6Option
		for _, o := range dhcp6.Options {
			opts = append(opts, &types.DHCPv6Option{
				Data:   o.Data,
				Length: int32(o.Length),
				Code:   int32(o.Code),
			})
		}
		return &types.DHCPv6{
			Timestamp:     timestamp,
			MsgType:       int32(dhcp6.MsgType),
			HopCount:      int32(dhcp6.HopCount),
			LinkAddr:      dhcp6.LinkAddr.String(),
			PeerAddr:      dhcp6.PeerAddr.String(),
			TransactionID: []byte(dhcp6.TransactionID),
			Options:       opts,
		}
	}
	return nil
})
