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

var dhcpv4Decoder = newGoPacketDecoder(
	types.Type_NC_DHCPv4,
	layers.LayerTypeDHCPv4,
	"The Dynamic Host Configuration Protocol (DHCP) is a network management protocol used on Internet Protocol networks whereby a DHCP server dynamically assigns an IP address and other network configuration parameters to each device on a network so they can communicate with other IP networks",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if dhcp4, ok := layer.(*layers.DHCPv4); ok {

			var (
				opts   []*types.DHCPOption
				fp     strings.Builder
				length = len(dhcp4.Options) - 1
			)
			for i, o := range dhcp4.Options {
				opts = append(opts, &types.DHCPOption{
					Data:   string(o.Data),
					Length: int32(o.Length),
					Type:   int32(o.Type),
				})
				fp.WriteString(strconv.Itoa(int(o.Type)))
				if i != length {
					fp.WriteString(",")
				}
			}

			return &types.DHCPv4{
				Timestamp:    timestamp,
				Operation:    int32(dhcp4.Operation),
				HardwareType: int32(dhcp4.HardwareType),
				HardwareLen:  int32(dhcp4.HardwareLen),
				HardwareOpts: int32(dhcp4.HardwareOpts),
				Xid:          dhcp4.Xid,
				Secs:         int32(dhcp4.Secs),
				Flags:        int32(dhcp4.Flags),
				ClientIP:     dhcp4.ClientIP.String(),
				YourClientIP: dhcp4.YourClientIP.String(),
				NextServerIP: dhcp4.NextServerIP.String(),
				RelayAgentIP: dhcp4.RelayAgentIP.String(),
				ClientHWAddr: dhcp4.ClientHWAddr.String(),
				ServerName:   dhcp4.ServerName,
				File:         dhcp4.File,
				Options:      opts,
				Fingerprint:  fp.String(),
			}
		}

		return nil
	},
)
