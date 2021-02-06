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

	"github.com/dreadl0ck/gopacket/layers"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toDNSResponseCodes() {
	var (
		// dns response code to number of occurrences
		codes    = make(map[int32]int64)
		pathName string
	)

	netmaltego.DNSTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, d *types.DNS, min, max uint64, path string, ipaddr string) {
			if pathName == "" {
				pathName = path
			}
			codes[d.ResponseCode]++
		},
		true,
	)

	trx := &maltego.Transform{}
	for code, num := range codes {
		ent := addEntityWithPath(trx, "netcap.DNSResponseCode", layers.DNSResponseCode(code).String(), pathName)
		ent.AddProperty("code", "Code", maltego.Strict, strconv.Itoa(int(code)))
		ent.SetLinkLabel(strconv.Itoa(int(num)))
		// TODO: num pkts / set thickness
		// ent.SetLinkThickness(maltego.GetThickness(uint64(service.BytesServer), min, max))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
