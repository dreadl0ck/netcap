package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToProducts() {
	maltego.SoftwareTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, soft *types.Software, min, max uint64, profilesFile string, mac string, ipaddr string) {

			ent := trx.AddEntity("netcap.Software", soft.Product)
			ent.SetType("netcap.Software")
			ent.SetValue(soft.Vendor + " " + soft.Product + " " + soft.Version)

			ent.SetLinkColor("#000000")
			//ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
		},
	)
}
