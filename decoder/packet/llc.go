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

var llcDecoder = newGoPacketDecoder(
	types.Type_NC_LLC,
	layers.LayerTypeLLC,
	"The LLC sublayer acts as an interface between the media access control sublayer and the network layer",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if llc, ok := layer.(*layers.LLC); ok {
			return &types.LLC{
				Timestamp: timestamp,
				DSAP:      int32(llc.DSAP),
				IG:        llc.IG,
				SSAP:      int32(llc.SSAP),
				CR:        llc.CR,
				Control:   int32(llc.Control),
			}
		}

		return nil
	},
)
