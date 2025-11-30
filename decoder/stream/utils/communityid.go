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

package utils

import (
	"net"

	"github.com/satta/gommunityid"
)

// communityIDGenerator is a reusable Community ID v1 generator.
// See: https://github.com/corelight/community-id-spec
var communityIDGenerator = gommunityid.CommunityIDv1{
	Seed: 0, // default seed
}

// CalcCommunityIDTCP calculates a Community ID v1 for a TCP stream.
// Returns an empty string if the IP addresses cannot be parsed.
func CalcCommunityIDTCP(srcIP, dstIP string, srcPort, dstPort uint16) string {
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)
	if src == nil || dst == nil {
		return ""
	}
	ft := gommunityid.MakeFlowTupleTCP(src, dst, srcPort, dstPort)
	return communityIDGenerator.CalcBase64(ft)
}

// CalcCommunityIDUDP calculates a Community ID v1 for a UDP stream.
// Returns an empty string if the IP addresses cannot be parsed.
func CalcCommunityIDUDP(srcIP, dstIP string, srcPort, dstPort uint16) string {
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)
	if src == nil || dst == nil {
		return ""
	}
	ft := gommunityid.MakeFlowTupleUDP(src, dst, srcPort, dstPort)
	return communityIDGenerator.CalcBase64(ft)
}

// CalcCommunityIDSCTP calculates a Community ID v1 for an SCTP stream.
// Returns an empty string if the IP addresses cannot be parsed.
func CalcCommunityIDSCTP(srcIP, dstIP string, srcPort, dstPort uint16) string {
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)
	if src == nil || dst == nil {
		return ""
	}
	ft := gommunityid.MakeFlowTupleSCTP(src, dst, srcPort, dstPort)
	return communityIDGenerator.CalcBase64(ft)
}

