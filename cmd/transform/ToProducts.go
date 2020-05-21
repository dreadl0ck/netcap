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

			ent.AddProperty("timestamp", "Timestamp", "strict", soft.Timestamp)
			ent.AddProperty("vendor", "Vendor", "strict", soft.Vendor)
			ent.AddProperty("product", "Product", "strict", soft.Product)
			ent.AddProperty("version", "Version", "strict", soft.Version)
			ent.AddProperty("sourcename", "SourceName", "strict", soft.SourceName)
			ent.AddProperty("sourcedata", "SourceData", "strict", maltego.EscapeText(soft.SourceData))
			ent.AddProperty("notes", "Notes", "strict", soft.Notes)

			ent.SetLinkColor("#000000")
			//ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
		},
	)
}
