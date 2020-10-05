package transform

import (
	"fmt"
	"strconv"

	"github.com/dreadl0ck/gopacket/layers"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toDNSOpCodes() {
	var (
		// dns op code to number of occurrences
		codes    = make(map[int32]int64)
		pathName string
	)

	maltego.DNSTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, d *types.DNS, min, max uint64, path string, ipaddr string) {
			if pathName == "" {
				pathName = path
			}
			codes[d.OpCode]++
		},
		true,
	)

	trx := maltego.Transform{}
	for code, num := range codes {
		ent := trx.AddEntityWithPath("netcap.DNSOpCode", layers.DNSOpCode(code).String(), pathName)
		ent.AddProperty("code", "Code", maltego.Strict, strconv.Itoa(int(code)))
		ent.SetLinkLabel(strconv.Itoa(int(num)))
		// TODO: num pkts / set thickness
		// ent.SetLinkThickness(maltego.GetThickness(uint64(service.BytesServer), min, max))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
