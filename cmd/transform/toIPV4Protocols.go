package transform

import (
	"fmt"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func toIPV4Protocols() {
	var (
		ipProtos = make(map[int32]int)
		pathName string
	)

	maltego.IPv4Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, ip *types.IPv4, min, max uint64, path string, mac string, ipaddr string) {
			if path == "" {
				pathName = path
			}
			ipProtos[ip.Protocol]++
		},
		true,
	)

	trx := maltego.Transform{}
	for val, numHits := range ipProtos {
		ent := trx.AddEntityWithPath("netcap.IPProtocol", layers.IPProtocol(uint8(val)).String(), pathName)
		ent.AddProperty("value", "Value", maltego.Strict, strconv.Itoa(int(val)))
		ent.SetLinkLabel(strconv.Itoa(numHits))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
