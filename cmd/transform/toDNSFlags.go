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

func toDNSFlagCombinations() {
	var (
		// dns flags to number of occurrences
		flags    = make(map[string]int64)
		pathName string
	)

	netmaltego.DNSTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, d *types.DNS, min, max uint64, path string, ipaddr string) {
			if pathName == "" {
				pathName = path
			}
			flags[dnsFlagsToString(d)]++
		},
		true,
	)

	trx := &maltego.Transform{}
	for flagCombination, num := range flags {
		ent := addEntityWithPath(trx, "netcap.DNSFlagCombination", flagCombination, pathName)
		ent.AddProperty("flags", "Flags", maltego.Strict, flagCombination)
		ent.SetLinkLabel(strconv.Itoa(int(num)))
		// TODO: num pkts / set thickness
		// ent.SetLinkThickness(maltego.GetThickness(uint64(service.BytesServer), min, max))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}

func dnsFlagsToString(dns *types.DNS) string {
	arr := make([]string, 0, 9)

	if dns.AA {
		arr = append(arr, "AA")
	}

	if dns.QR {
		arr = append(arr, "QR")
	}

	if dns.RA {
		arr = append(arr, "RA")
	}

	if dns.RD {
		arr = append(arr, "RD")
	}

	if dns.TC {
		arr = append(arr, "TC")
	}

	// AD?

	return strings.Join(arr, ",")
}
