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
	"encoding/binary"
	"fmt"
	"net"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// PIM type names
var pimTypeNames = map[uint8]string{
	0:  "Hello",
	1:  "Register",
	2:  "Register-Stop",
	3:  "Join/Prune",
	4:  "Bootstrap",
	5:  "Assert",
	6:  "Graft",
	7:  "Graft-Ack",
	8:  "Candidate-RP-Advertisement",
	9:  "State-Refresh",
	10: "DF-Election",
}

var pimDecoder = newPacketDecoder(
	types.Type_NC_PIM,
	"PIM",
	"Protocol Independent Multicast is a family of multicast routing protocols for IP networks",
	nil,
	func(p gopacket.Packet) proto.Message {
		// PIM uses IP protocol number 103
		var payload []byte
		var srcIP, dstIP string

		// Try IPv4 first
		if ipLayer := p.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, ok := ipLayer.(*layers.IPv4)
			if ok && ip.Protocol == 103 {
				payload = ip.Payload
				srcIP = ip.SrcIP.String()
				dstIP = ip.DstIP.String()
			}
		}

		// Try IPv6 if no IPv4 match
		if payload == nil {
			if ip6Layer := p.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
				ip6, ok := ip6Layer.(*layers.IPv6)
				if ok && ip6.NextHeader == 103 {
					payload = ip6.Payload
					srcIP = ip6.SrcIP.String()
					dstIP = ip6.DstIP.String()
				}
			}
		}

		if len(payload) < 4 {
			return nil
		}

		version := (payload[0] >> 4) & 0xF
		pimType := payload[0] & 0xF
		checksum := binary.BigEndian.Uint16(payload[2:4])

		typeName := pimTypeNames[pimType]
		if typeName == "" {
			typeName = fmt.Sprintf("Unknown(%d)", pimType)
		}

		// Extract group addresses from Join/Prune messages
		var groupAddresses []string
		if pimType == 3 && len(payload) >= 26 { // Join/Prune
			// PIM Join/Prune: after header (4 bytes) + upstream neighbor (6 bytes) + reserved (1) + holdtime (2) + num groups (1)
			// offset 14 for first group entry
			offset := 14
			if offset < len(payload) {
				numGroups := int(payload[13])
				for i := 0; i < numGroups && offset+8 <= len(payload); i++ {
					// Group address: addr_family(1) + encoding_type(1) + reserved(1) + mask_len(1) + group_addr(4 for IPv4)
					if payload[offset] == 1 && offset+8 <= len(payload) { // IPv4
						groupIP := net.IP(payload[offset+4 : offset+8])
						groupAddresses = append(groupAddresses, groupIP.String())
						offset += 8

						// Skip join and prune sources
						if offset+4 <= len(payload) {
							numJoined := binary.BigEndian.Uint16(payload[offset : offset+2])
							numPruned := binary.BigEndian.Uint16(payload[offset+2 : offset+4])
							offset += 4
							offset += int(numJoined+numPruned) * 8
						}
					} else {
						break
					}
				}
			}
		}

		return &types.PIM{
			Timestamp:      p.Metadata().Timestamp.UnixNano(),
			Version:        int32(version),
			Type:           int32(pimType),
			TypeName:       typeName,
			Checksum:       int32(checksum),
			GroupAddresses: groupAddresses,
			SrcIP:          srcIP,
			DstIP:          dstIP,
		}
	},
	nil,
)
