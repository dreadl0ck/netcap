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
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
)

var lcmEncoder = CreateLayerEncoder(types.Type_NC_LCM, layers.LayerTypeLCM, func(layer gopacket.Layer, timestamp string) proto.Message {
	if lcm, ok := layer.(*layers.LCM); ok {
		return &types.LCM{
			Timestamp:      timestamp,
			Magic:          int32(lcm.Magic),
			SequenceNumber: int32(lcm.SequenceNumber),
			PayloadSize:    int32(lcm.PayloadSize),
			FragmentOffset: int32(lcm.FragmentOffset),
			FragmentNumber: int32(lcm.FragmentNumber),
			TotalFragments: int32(lcm.TotalFragments),
			ChannelName:    string(lcm.ChannelName),
			Fragmented:     bool(lcm.Fragmented),
		}
	}
	return nil
})
