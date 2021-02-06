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

package transform

import (
	"fmt"
	netmaltego "github.com/dreadl0ck/netcap/maltego"
	"strconv"
	"strings"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toTCPFlagCombinations() {
	var (
		idents   = make(map[string]int)
		pathName string
	)

	netmaltego.TCPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, tcp *types.TCP, min, max uint64, path string, ipaddr string) {
			if pathName == "" {
				pathName = path
			}
			idents[tcpFlagsToString(tcp)]++
		},
		true,
	)

	trx := &maltego.Transform{}
	for flags, numHits := range idents {
		ent := addEntityWithPath(trx, "netcap.TCPFlag", flags, pathName)
		ent.SetLinkLabel(strconv.Itoa(numHits))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}

func tcpFlagsToString(tcp *types.TCP) string {
	arr := make([]string, 0, 9)

	if tcp.FIN {
		arr = append(arr, "FIN")
	}

	if tcp.SYN {
		arr = append(arr, "SYN")
	}

	if tcp.RST {
		arr = append(arr, "RST")
	}

	if tcp.PSH {
		arr = append(arr, "PSH")
	}

	if tcp.ACK {
		arr = append(arr, "ACK")
	}

	if tcp.URG {
		arr = append(arr, "URG")
	}

	if tcp.ECE {
		arr = append(arr, "ECE")
	}

	if tcp.CWR {
		arr = append(arr, "CWR")
	}

	if tcp.NS {
		arr = append(arr, "NS")
	}

	return strings.Join(arr, ",")
}
