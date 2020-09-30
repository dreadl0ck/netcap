package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func toNTPReferenceIDs() {

	var (
		ids      = make(map[uint32]int)
		pathName string
	)

	maltego.NTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, ntp *types.NTP, min, max uint64, path string, ipaddr string) {
			if pathName == "" {
				pathName = path
			}
			ids[ntp.ReferenceID]++
		},
		true,
	)

	trx := maltego.Transform{}
	for val, numHits := range ids {
		ent := trx.AddEntityWithPath("netcap.NTPReferenceID", strconv.FormatUint(uint64(val), 10), pathName)
		ent.AddProperty("value", "Value", maltego.Strict, strconv.Itoa(int(val)))
		ent.SetLinkLabel(strconv.Itoa(numHits))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
