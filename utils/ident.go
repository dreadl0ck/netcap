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
	"strings"

	"github.com/gopacket/gopacket"
)

var flowIdentReplacer = strings.NewReplacer(":", "-", "->", "--")

// CleanIdent will clean a path
func CleanIdent(path string) string {
	return flowIdentReplacer.Replace(path)
}

// CreateFlowIdentFromLayerFlows creates a flow identifier string.
// format: srcIP:srcPort->dstIP:dstPort
func CreateFlowIdentFromLayerFlows(net gopacket.Flow, trans gopacket.Flow) string {
	// IPv4:
	// echo "255.255.255.255:65000->255.255.255.255:65000" | wc -c
	// 45
	// TODO: handle IPv6
	// TODO: compare byte slice performance VS strings.Builder
	b := make([]byte, 0, 45)

	// Safely handle network endpoints
	if len(net.Src().Raw()) > 0 {
		b = append(b, []byte(net.Src().String())...)
	}
	b = append(b, []byte(":")...)

	// Safely handle transport endpoints - check for valid data before converting to string
	if len(trans.Src().Raw()) > 0 {
		b = append(b, []byte(trans.Src().String())...)
	}
	b = append(b, []byte("->")...)

	if len(net.Dst().Raw()) > 0 {
		b = append(b, []byte(net.Dst().String())...)
	}
	b = append(b, []byte(":")...)

	if len(trans.Dst().Raw()) > 0 {
		b = append(b, []byte(trans.Dst().String())...)
	}

	return string(b)
}

// CreateFlowIdent creates a flow identifier string.
// format: srcIP:srcPort->dstIP:dstPort
func CreateFlowIdent(srcIP, srcPort, dstIP, dstPort string) string {
	// IPv4:
	// echo "255.255.255.255:65000->255.255.255.255:65000" | wc -c
	// 45
	// TODO: handle IPv6
	// TODO: compare byte slice performance VS strings.Builder
	b := make([]byte, 0, 45)

	b = append(b, []byte(srcIP)...)
	b = append(b, []byte(":")...)
	b = append(b, []byte(srcPort)...)
	b = append(b, []byte("->")...)
	b = append(b, []byte(dstIP)...)
	b = append(b, []byte(":")...)
	b = append(b, []byte(dstPort)...)

	return string(b)
}

// ReverseFlowIdent reverses the flow identifier.
// e.g: 192.168.1.47:53032->165.227.109.154:80
// will return: 165.227.109.154:80->192.168.1.47:53032
// TODO: benchmark and improve performance
// TODO: IPv6
func ReverseFlowIdent(i string) string {
	arr := strings.Split(i, "->")
	if len(arr) != 2 {
		return ""
	}

	src := strings.Split(arr[0], ":")
	if len(src) != 2 {
		return ""
	}

	dst := strings.Split(arr[1], ":")
	if len(dst) != 2 {
		return ""
	}

	return CreateFlowIdent(dst[0], dst[1], src[0], src[1])
}

// ParseFlowIdent parses the flow identifier.
// e.g: 192.168.1.47:53032->165.227.109.154:80
// will return: 192.168.1.47, 53032, 165.227.109.154, 80
// TODO: benchmark and improve performance
// TODO: IPv6
func ParseFlowIdent(i string) (srcIP, srcPort, dstIP, dstPort string) {
	arr := strings.Split(i, "->")
	if len(arr) != 2 {
		return
	}

	src := strings.Split(arr[0], ":")
	if len(src) != 2 {
		return
	}

	dst := strings.Split(arr[1], ":")
	if len(dst) != 2 {
		return
	}

	return src[0], src[1], dst[0], dst[1]
}
