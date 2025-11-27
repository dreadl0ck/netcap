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

var pppDecoder = newGoPacketDecoder(
	types.Type_NC_PPP,
	layers.LayerTypePPP,
	"PPP (Point-to-Point Protocol) is a data link layer protocol used to establish direct connections between two nodes",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if ppp, ok := layer.(*layers.PPP); ok {
			// PPP Type values
			const (
				PPPTypeIPv4         = 0x0021
				PPPTypeIPv6         = 0x0057
				PPPTypeLCP          = 0xc021 // Link Control Protocol
				PPPTypePAP          = 0xc023 // Password Authentication Protocol
				PPPTypeCHAP         = 0xc223 // Challenge Handshake Authentication Protocol
				PPPTypeIPCP         = 0x8021 // IP Control Protocol
				PPPTypeIPv6CP       = 0x8057 // IPv6 Control Protocol
			)

			pppType := uint16(ppp.PPPType)
			isControlProtocol := pppType == PPPTypeLCP || pppType == PPPTypePAP ||
				pppType == PPPTypeCHAP || pppType == PPPTypeIPCP || pppType == PPPTypeIPv6CP
			isAuthentication := pppType == PPPTypePAP || pppType == PPPTypeCHAP

			return &types.PPP{
				Timestamp:         timestamp,
				PPPType:           int32(ppp.PPPType),
				PPPTypeName:       ppp.PPPType.String(),
				HasPPTPHeader:     ppp.HasPPTPHeader,
				IsControlProtocol: isControlProtocol,
				IsAuthentication:  isAuthentication,
				IsIPv4:            pppType == PPPTypeIPv4,
				IsIPv6:            pppType == PPPTypeIPv6,
			}
		}

		return nil
	},
)

