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
	"strconv"
	"strings"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

var dhcpv6Decoder = newGoPacketDecoder(
	types.Type_NC_DHCPv6,
	layers.LayerTypeDHCPv6,
	"The Dynamic Host Configuration Protocol (DHCP) is a network management protocol used on Internet Protocol networks whereby a DHCP server dynamically assigns an IP address and other network configuration parameters to each device on a network so they can communicate with other IP networks",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if dhcp6, ok := layer.(*layers.DHCPv6); ok {

			var (
				opts   []*types.DHCPv6Option
				fp     strings.Builder
				length = len(dhcp6.Options) - 1
			)
			for i, o := range dhcp6.Options {
				opts = append(opts, &types.DHCPv6Option{
					Data:   string(o.Data),
					Length: int32(o.Length),
					Code:   int32(o.Code),
				})
				fp.WriteString(strconv.Itoa(int(o.Code)))
				if i != length {
					fp.WriteString(",")
				}
			}

			return &types.DHCPv6{
				Timestamp:     timestamp,
				MsgType:       int32(dhcp6.MsgType),
				HopCount:      int32(dhcp6.HopCount),
				LinkAddr:      dhcp6.LinkAddr.String(),
				PeerAddr:      dhcp6.PeerAddr.String(),
				TransactionID: dhcp6.TransactionID,
				Options:       opts,
				Fingerprint:   fp.String(),
			}
		}

		return nil
	},
)
