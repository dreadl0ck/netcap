package transform

import (
	"fmt"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func toLinkTypes() {
	var (
		linkTypes = make(map[int32]int)
		pathName  string
	)

	maltego.ARPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, a *types.ARP, min, max uint64, path string, mac string) {
			if pathName == "" {
				pathName = path
			}
			linkTypes[a.AddrType]++
		},
		true,
	)

	trx := maltego.Transform{}
	for val, numHits := range linkTypes {
		ent := trx.AddEntityWithPath("netcap.LinkType", layers.LinkType(uint8(val)).String(), pathName)
		ent.AddProperty("value", "Value", maltego.Strict, strconv.Itoa(int(val)))
		ent.SetLinkLabel(strconv.Itoa(numHits))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
