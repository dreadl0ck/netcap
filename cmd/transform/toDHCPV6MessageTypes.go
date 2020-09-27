package transform

import (
	"fmt"
	"github.com/dreadl0ck/gopacket/layers"
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toDHCPV6MessageTypes() {
	var (
		msgTypes = make(map[int32]int)
		pathName string
	)

	maltego.DHCPV6Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, d *types.DHCPv6, min, max uint64, path string, mac string) {
			if path == "" {
				pathName = path
			}
			msgTypes[d.MsgType]++
		},
		true,
	)

	trx := maltego.Transform{}
	for val, numHits := range msgTypes {
		ent := trx.AddEntityWithPath("netcap.DHCPv6MessageType", layers.DHCPv6MsgType(byte(val)).String(), pathName)
		ent.AddProperty("value", "Value", maltego.Strict, strconv.Itoa(int(val)))
		ent.SetLinkLabel(strconv.Itoa(numHits))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
