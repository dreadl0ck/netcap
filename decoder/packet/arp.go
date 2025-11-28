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
	"bytes"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// arpOperationNames maps ARP operation codes to human-readable names
var arpOperationNames = map[uint16]string{
	1: "Request",
	2: "Reply",
	3: "RARP Request",
	4: "RARP Reply",
}

// zeroIPv4 represents 0.0.0.0
var zeroIPv4 = []byte{0, 0, 0, 0}

var arpDecoder = newGoPacketDecoder(
	types.Type_NC_ARP,
	layers.LayerTypeARP,
	"The Address Resolution Protocol resolves IP to hardware addresses",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if arp, ok := layer.(*layers.ARP); ok {
			srcProtoAddr := parseIPv4(arp.SourceProtAddress)
			dstProtoAddr := parseIPv4(arp.DstProtAddress)

			// Determine operation name
			opName := arpOperationNames[arp.Operation]
			if opName == "" {
				opName = "Unknown"
			}

			// Gratuitous ARP: reply sent without being requested, or request for own IP
			// Common pattern: sender IP == target IP in a reply
			isGratuitous := arp.Operation == 2 && bytes.Equal(arp.SourceProtAddress, arp.DstProtAddress)

			// ARP Probe: sender IP is 0.0.0.0 (used for duplicate address detection)
			isProbe := bytes.Equal(arp.SourceProtAddress, zeroIPv4)

			// ARP Announcement: sender IP == target IP in a request
			isAnnouncement := arp.Operation == 1 && bytes.Equal(arp.SourceProtAddress, arp.DstProtAddress)

			return &types.ARP{
				Timestamp:           timestamp,
				AddrType:            int32(arp.AddrType),
				Protocol:            int32(arp.Protocol),
				HwAddressSize:       int32(arp.HwAddressSize),
				ProtocolAddressSize: int32(arp.ProtAddressSize),
				Operation:           int32(arp.Operation),
				SrcHwAddress:        formatMac(arp.SourceHwAddress),
				SrcProtocolAddress:  srcProtoAddr,
				DstHwAddress:        formatMac(arp.DstHwAddress),
				DstProtocolAddress:  dstProtoAddr,
				IsGratuitous:        isGratuitous,
				IsProbe:             isProbe,
				IsAnnouncement:      isAnnouncement,
				OperationName:       opName,
			}
		}

		return nil
	},
)
