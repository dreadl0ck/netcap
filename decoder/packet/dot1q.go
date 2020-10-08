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

var dot1QDecoder = newGoPacketDecoder(
	types.Type_NC_Dot1Q,
	layers.LayerTypeDot1Q,
	"IEEE 802.11 is part of the IEEE 802 set of local area network protocols, and specifies the set of media access control and physical layer protocols for implementing wireless local area network Wi-Fi",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if dot1q, ok := layer.(*layers.Dot1Q); ok {
			return &types.Dot1Q{
				Timestamp:      timestamp,
				Priority:       int32(dot1q.Priority),
				DropEligible:   dot1q.DropEligible,
				VLANIdentifier: int32(dot1q.VLANIdentifier),
				Type:           int32(dot1q.Type),
			}
		}

		return nil
	},
)
