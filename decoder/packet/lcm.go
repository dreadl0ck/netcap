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

var lcmDecoder = newGoPacketDecoder(
	types.Type_NC_LCM,
	layers.LayerTypeLCM,
	"LCM is a set of libraries and tools for message passing and data marshaling, targeted at real-time systems where high-bandwidth and low latency are critical",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if lcm, ok := layer.(*layers.LCM); ok {
			return &types.LCM{
				Timestamp:      timestamp,
				Magic:          int32(lcm.Magic),
				SequenceNumber: int32(lcm.SequenceNumber),
				PayloadSize:    int32(lcm.PayloadSize),
				FragmentOffset: int32(lcm.FragmentOffset),
				FragmentNumber: int32(lcm.FragmentNumber),
				TotalFragments: int32(lcm.TotalFragments),
				ChannelName:    lcm.ChannelName,
				Fragmented:     lcm.Fragmented,
			}
		}

		return nil
	},
)
