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
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// getRMCPClassName returns a human-readable name for the RMCP class
func getRMCPClassName(class layers.RMCPClass) string {
	switch class {
	case 0x06:
		return "ASF"
	case 0x07:
		return "IPMI"
	case 0x08:
		return "OEM"
	default:
		return "Unknown"
	}
}

// RMCP class constants
const (
	RMCPClassASF  = 0x06
	RMCPClassIPMI = 0x07
)

var rmcpDecoder = newGoPacketDecoder(
	types.Type_NC_RMCP,
	layers.LayerTypeRMCP,
	"RMCP (Remote Management Control Protocol) is used for remote management of devices, commonly in IPMI/BMC systems",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if rmcp, ok := layer.(*layers.RMCP); ok {
			class := uint8(rmcp.Class)
			return &types.RMCP{
				Timestamp:     timestamp,
				Version:       int32(rmcp.Version),
				Sequence:      int32(rmcp.Sequence),
				Ack:           rmcp.Ack,
				Class:         int32(rmcp.Class),
				ClassName:     getRMCPClassName(rmcp.Class),
				IsIPMI:        class == RMCPClassIPMI,
				IsASF:         class == RMCPClassASF,
				NoAckRequired: rmcp.Sequence == 255,
			}
		}

		return nil
	},
)

