package transform

import (
	"fmt"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func toIGMPGroupRecordTypes() {
	var (
		igmpTypes = make(map[int32]int)
		pathName string
	)

	maltego.IGMPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, i *types.IGMP, min, max uint64, path string, mac string) {
			if path == "" {
				pathName = path
			}
			for _, r := range i.GroupRecords {
				igmpTypes[r.Type]++
			}
		},
		true,
	)

	trx := maltego.Transform{}
	for val, numHits := range igmpTypes {
		ent := trx.AddEntityWithPath("netcap.IGMPGroupRecordType", layers.IGMPv3GroupRecordType(uint8(val)).String(), pathName)
		ent.AddProperty("value", "Value", maltego.Strict, strconv.Itoa(int(val)))
		ent.SetLinkLabel(strconv.Itoa(numHits))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}

