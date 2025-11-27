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

var pppoeDecoder = newGoPacketDecoder(
	types.Type_NC_PPPoE,
	layers.LayerTypePPPoE,
	"PPPoE (Point-to-Point Protocol over Ethernet) encapsulates PPP frames inside Ethernet frames, commonly used for DSL connections",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if pppoe, ok := layer.(*layers.PPPoE); ok {
			// PPPoE code values from RFC 2516
			const (
				PPPoECodePADI = 0x09 // Active Discovery Initiation
				PPPoECodePADO = 0x07 // Active Discovery Offer
				PPPoECodePADR = 0x19 // Active Discovery Request
				PPPoECodePADS = 0x65 // Active Discovery Session-confirmation
				PPPoECodePADT = 0xa7 // Active Discovery Terminate
			)

			code := uint8(pppoe.Code)
			isDiscovery := code == PPPoECodePADI || code == PPPoECodePADO ||
				code == PPPoECodePADR || code == PPPoECodePADS

			return &types.PPPoE{
				Timestamp:            timestamp,
				Version:              int32(pppoe.Version),
				Type:                 int32(pppoe.Type),
				Code:                 int32(pppoe.Code),
				CodeName:             pppoe.Code.String(),
				SessionId:            int32(pppoe.SessionId),
				Length:               int32(pppoe.Length),
				IsDiscovery:          isDiscovery,
				IsSessionTermination: code == PPPoECodePADT,
				IsSessionEstablished: code == PPPoECodePADS,
			}
		}

		return nil
	},
)

