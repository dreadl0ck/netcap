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

import "strings"

// ChopTransportIdent returns the transport part of a flow identifier
// e.g: 192.168.1.47->165.227.109.154-53032->80
// will return: 53032->80.
// func ChopTransportIdent(in string) string {
//	arr := strings.Split(in, "-")
//	if len(arr) != 4 {
//		return ""
//	}
//
//	return arr[2] + "-" + arr[3]
// }

// ReverseIdent reverses the flow identifier
// e.g: 192.168.1.47->165.227.109.154-53032->80
// will return: 165.227.109.154->192.168.1.47-80->53032.
func ReverseIdent(i string) string {
	arr := strings.Split(i, "->")
	if len(arr) != 3 {
		return ""
	}

	middle := strings.Split(arr[1], "-")
	if len(middle) != 2 {
		return ""
	}

	return middle[0] + "->" + arr[0] + "-" + arr[2] + "->" + middle[1]
}

// ParseIdent parses the flow identifier
// e.g: 192.168.1.47->165.227.109.154-53032->80
// will return: 192.168.1.47, 53032, 165.227.109.154, 80.
func ParseIdent(i string) (srcIP, srcPort, dstIP, dstPort string) {
	arr := strings.Split(i, "->")
	if len(arr) != 3 {
		return
	}

	middle := strings.Split(arr[1], "-")
	if len(middle) != 2 {
		return
	}

	return arr[0], middle[1], middle[0], arr[2]
}
