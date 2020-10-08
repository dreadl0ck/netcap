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

var nortelDiscoveryDecoder = newGoPacketDecoder(
	types.Type_NC_NortelDiscovery,
	layers.LayerTypeNortelDiscovery,
	"The Nortel Discovery Protocol (NDP) is a Data Link Layer (OSI Layer 2) network protocol for discovery of Nortel networking devices and certain products from Avaya and Ciena",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if nortel, ok := layer.(*layers.NortelDiscovery); ok {
			return &types.NortelDiscovery{
				Timestamp: timestamp,
				IPAddress: string(nortel.IPAddress),
				SegmentID: nortel.SegmentID,
				Chassis:   int32(nortel.Chassis),
				Backplane: int32(nortel.Backplane),
				State:     int32(nortel.State),
				NumLinks:  int32(nortel.NumLinks),
			}
		}

		return nil
	},
)
