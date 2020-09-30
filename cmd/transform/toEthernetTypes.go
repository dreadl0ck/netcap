package transform

import (
	"fmt"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func toEthernetTypes() {
	var (
		etherTypes = make(map[int32]int)
		pathName   string
	)

	maltego.EthernetTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, eth *types.Ethernet, min, max uint64, path string, ipaddr string) {
			if pathName == "" {
				pathName = path
			}
			etherTypes[eth.EthernetType]++
		},
		true,
	)

	trx := maltego.Transform{}
	for typ, numHits := range etherTypes {
		ent := trx.AddEntityWithPath("netcap.EthernetType", layers.EthernetType(uint16(typ)).String(), pathName)
		ent.AddProperty("type", "Type", maltego.Strict, strconv.Itoa(int(typ)))
		ent.SetLinkLabel(strconv.Itoa(numHits))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
