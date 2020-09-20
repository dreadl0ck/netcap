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

package utils

import (
	"strings"

	"github.com/dreadl0ck/gopacket"
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

	b = append(b, []byte(net.Src().String())...)
	b = append(b, []byte(":")...)
	b = append(b, []byte(trans.Src().String())...)
	b = append(b, []byte("->")...)
	b = append(b, []byte(net.Dst().String())...)
	b = append(b, []byte(":")...)
	b = append(b, []byte(trans.Dst().String())...)

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
