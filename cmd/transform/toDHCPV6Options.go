package transform

import (
	"fmt"
	"github.com/dreadl0ck/gopacket/layers"
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toDHCPV6Options() {
	var (
		opts     = make(map[int32]int)
		pathName string
	)

	maltego.DHCPV6Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, d *types.DHCPv6, min, max uint64, path string, mac string) {
			if pathName == "" {
				pathName = path
			}
			for _, o := range d.Options {
				opts[o.Code]++
			}
		},
		true,
	)

	trx := maltego.Transform{}
	for val, numHits := range opts {
		ent := trx.AddEntityWithPath("netcap.DHCPv6Option", layers.DHCPv6Opt(uint16(val)).String(), pathName)
		ent.AddProperty("value", "Value", maltego.Strict, strconv.Itoa(int(val)))
		ent.SetLinkLabel(strconv.Itoa(numHits))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
