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

func toEthernetTypes() {
	var (
		etherTypes = make(map[int32]int)
		pathName   string
	)

	netmaltego.EthernetTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, eth *types.Ethernet, min, max uint64, path string, ipaddr string) {
			if pathName == "" {
				pathName = path
			}
			etherTypes[eth.EthernetType]++
		},
		true,
	)

	trx := &maltego.Transform{}
	for typ, numHits := range etherTypes {
		ent := addEntityWithPath(trx, "netcap.EthernetType", layers.EthernetType(uint16(typ)).String(), pathName)
		ent.AddProperty("type", "Type", maltego.Strict, strconv.Itoa(int(typ)))
		ent.SetLinkLabel(strconv.Itoa(numHits))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
