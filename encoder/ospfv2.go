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

var ospfv2Encoder = CreateLayerEncoder(types.Type_NC_OSPFv2, layers.LayerTypeOSPF, func(layer gopacket.Layer, timestamp string) proto.Message {
	if ospf2, ok := layer.(*layers.OSPFv2); ok {
		return &types.OSPFv2{
			Timestamp:      timestamp,
			Version:        int32(ospf2.Version),
			Type:           int32(ospf2.Type),
			PacketLength:   int32(ospf2.PacketLength),
			RouterID:       uint32(ospf2.RouterID),
			AreaID:         uint32(ospf2.AreaID),
			Checksum:       int32(ospf2.Checksum),
			AuType:         int32(ospf2.AuType),
			Authentication: int64(ospf2.Authentication),
		}
	}
	return nil
})
