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
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// ipv4ProtocolNames maps IP protocol numbers to names
var ipv4ProtocolNames = map[layers.IPProtocol]string{
	layers.IPProtocolICMPv4: "ICMP",
	layers.IPProtocolTCP:    "TCP",
	layers.IPProtocolUDP:    "UDP",
	layers.IPProtocolGRE:    "GRE",
	layers.IPProtocolSCTP:   "SCTP",
	layers.IPProtocolIPv6:   "IPv6",
	layers.IPProtocolIPIP:   "IPIP",
	layers.IPProtocolESP:    "ESP",
	layers.IPProtocolAH:     "AH",
}

// IPv4 Option Types
const (
	ipv4OptLSRR = 131 // Loose Source Record Route
	ipv4OptSSRR = 137 // Strict Source Record Route
	ipv4OptRR   = 7   // Record Route
)

var ipv4Decoder = newGoPacketDecoder(
	types.Type_NC_IPv4,
	layers.LayerTypeIPv4,
	"Internet Protocol version 4 is the fourth version of the Internet Protocol. It is one of the core protocols of standards-based internetworking methods in the Internet and other packet-switched networks",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if ip4, ok := layer.(*layers.IPv4); ok {
			var e float64
			if conf.CalculateEntropy {
				e = entropy(ip4.Payload)
			}

			var (
				opts           []*types.IPv4Option
				hasLSRR        bool
				hasSSRR        bool
				hasRecordRoute bool
			)

			for _, o := range ip4.Options {
				opts = append(opts, &types.IPv4Option{
					OptionData:   o.OptionData,
					OptionLength: int32(o.OptionLength),
					OptionType:   int32(o.OptionType),
				})

				// Check for security-relevant options
				switch o.OptionType {
				case ipv4OptLSRR:
					hasLSRR = true
				case ipv4OptSSRR:
					hasSSRR = true
				case ipv4OptRR:
					hasRecordRoute = true
				}
			}

			// Get protocol name
			protoName := ipv4ProtocolNames[ip4.Protocol]
			if protoName == "" {
				protoName = "Unknown"
			}

			// Build flags string
			var flagsArr []string
			if ip4.Flags&layers.IPv4DontFragment != 0 {
				flagsArr = append(flagsArr, "DF")
			}
			if ip4.Flags&layers.IPv4MoreFragments != 0 {
				flagsArr = append(flagsArr, "MF")
			}

			// Extract DSCP and ECN from TOS
			dscp := int32(ip4.TOS >> 2)
			ecn := int32(ip4.TOS & 0x03)

			return &types.IPv4{
				Timestamp:            timestamp,
				Version:              int32(ip4.Version),
				IHL:                  int32(ip4.IHL),
				TOS:                  int32(ip4.TOS),
				Length:               int32(ip4.Length),
				Id:                   int32(ip4.Id),
				Flags:                int32(ip4.Flags),
				FragOffset:           int32(ip4.FragOffset),
				TTL:                  int32(ip4.TTL),
				Protocol:             int32(ip4.Protocol),
				Checksum:             int32(ip4.Checksum),
				SrcIP:                ip4.SrcIP.String(),
				DstIP:                ip4.DstIP.String(),
				Padding:              ip4.Padding,
				Options:              opts,
				PayloadEntropy:       e,
				PayloadSize:          int32(len(ip4.Payload)),
				IsFragment:           ip4.FragOffset > 0 || (ip4.Flags&layers.IPv4MoreFragments) != 0,
				HasOptions:           ip4.IHL > 5,
				HasLooseSourceRoute:  hasLSRR,
				HasStrictSourceRoute: hasSSRR,
				HasRecordRoute:       hasRecordRoute,
				ProtocolName:         protoName,
				DSCP:                 dscp,
				ECN:                  ecn,
				FlagsStr:             strings.Join(flagsArr, ","),
			}
		}

		return nil
	},
)
