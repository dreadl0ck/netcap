/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package packet

import (
	"strconv"
	"strings"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

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
