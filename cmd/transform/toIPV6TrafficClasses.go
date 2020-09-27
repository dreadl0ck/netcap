package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func toIPV6TrafficClasses() {
	var (
		classes  = make(map[int32]int)
		pathName string
	)

	maltego.IPv6Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, ip *types.IPv6, min, max uint64, path string, mac string, ipaddr string) {
			if path == "" {
				pathName = path
			}
			classes[ip.TrafficClass]++
		},
		true,
	)

	trx := maltego.Transform{}
	for val, numHits := range classes {
		ent := trx.AddEntityWithPath("netcap.IPv6TrafficClass", strconv.Itoa(int(val)), pathName)
		ent.AddProperty("value", "Value", maltego.Strict, strconv.Itoa(int(val)))
		ent.SetLinkLabel(strconv.Itoa(numHits))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
