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

func toIGMPGroupRecordTypes() {
	var (
		igmpTypes = make(map[int32]int)
		pathName  string
	)

	netmaltego.IGMPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, i *types.IGMP, min, max uint64, path string, mac string) {
			if pathName == "" {
				pathName = path
			}
			for _, r := range i.GroupRecords {
				igmpTypes[r.Type]++
			}
		},
		true,
	)

	trx := &maltego.Transform{}
	for val, numHits := range igmpTypes {
		ent := addEntityWithPath(trx, "netcap.IGMPGroupRecordType", layers.IGMPv3GroupRecordType(uint8(val)).String(), pathName)
		ent.AddProperty("value", "Value", maltego.Strict, strconv.Itoa(int(val)))
		ent.SetLinkLabel(strconv.Itoa(numHits))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
