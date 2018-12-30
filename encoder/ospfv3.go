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

var ospfv3Encoder = CreateLayerEncoder(types.Type_NC_OSPFv3, layers.LayerTypeOSPF, func(layer gopacket.Layer, timestamp string) proto.Message {
	if ospf3, ok := layer.(*layers.OSPFv3); ok {
		return &types.OSPFv3{
			Timestamp:    timestamp,
			Version:      int32(ospf3.Version),
			Type:         int32(ospf3.Type),
			PacketLength: int32(ospf3.PacketLength),
			RouterID:     uint32(ospf3.RouterID),
			AreaID:       uint32(ospf3.AreaID),
			Checksum:     int32(ospf3.Checksum),
			Instance:     int32(ospf3.Instance),
			Reserved:     int32(ospf3.Reserved),
		}
	}
	return nil
})
