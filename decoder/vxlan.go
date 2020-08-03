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

package decoder

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

var vxlanDecoder = NewGoPacketDecoder(
	types.Type_NC_VXLAN,
	layers.LayerTypeVXLAN,
	"Virtual Extensible LAN is a network virtualization technology that attempts to address the scalability problems associated with large cloud computing deployments",
	func(layer gopacket.Layer, timestamp string) proto.Message {
		if vx, ok := layer.(*layers.VXLAN); ok {
			return &types.VXLAN{
				Timestamp:        timestamp,
				ValidIDFlag:      bool(vx.ValidIDFlag),
				VNI:              uint32(vx.VNI),
				GBPExtension:     bool(vx.GBPExtension),
				GBPDontLearn:     bool(vx.GBPDontLearn),
				GBPApplied:       bool(vx.GBPApplied),
				GBPGroupPolicyID: int32(vx.GBPGroupPolicyID),
			}
		}
		return nil
	},
)
