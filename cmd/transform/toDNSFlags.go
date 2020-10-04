package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
	"strings"
)

func toDNSFlagCombinations() {

	var (
		// dns flags to number of occurrences
		flags    = make(map[string]int64)
		pathName string
	)

	maltego.DNSTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, d *types.DNS, min, max uint64, path string, ipaddr string) {
			if pathName == "" {
				pathName = path
			}
			flags[dnsFlagsToString(d)]++
		},
		true,
	)

	trx := maltego.Transform{}
	for flagCombination, num := range flags {
		ent := trx.AddEntityWithPath("netcap.DNSFlagCombination", flagCombination, pathName)
		ent.AddProperty("flags", "Flags", maltego.Strict, flagCombination)
		ent.SetLinkLabel(strconv.Itoa(int(num)))
		// TODO: num pkts / set thickness
		//ent.SetLinkThickness(maltego.GetThickness(uint64(service.BytesServer), min, max))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}

func dnsFlagsToString(dns *types.DNS) string {

	var arr = make([]string, 0, 9)

	if dns.AA {
		arr = append(arr, "AA")
	}

	if dns.QR {
		arr = append(arr, "QR")
	}

	if dns.RA {
		arr = append(arr, "RA")
	}

	if dns.RD {
		arr = append(arr, "RD")
	}

	if dns.TC {
		arr = append(arr, "TC")
	}

	// AD?

	return strings.Join(arr, ",")
}
