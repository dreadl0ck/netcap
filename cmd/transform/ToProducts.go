package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strings"
)

func ToProducts() {
	maltego.SoftwareTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, soft *types.Software, min, max uint64, profilesFile string, mac string, ipaddr string) {

			val := soft.Vendor + " " + soft.Product + " " + soft.Version
			if len(soft.SourceName) > 0 {
				if soft.SourceName == "Generic version harvester" {
					if len(val) == 0 {
						val = soft.SourceData
					} else {
						val += "\n" + soft.SourceData
					}
				}
				val += "\n" + soft.SourceName
			}
			for i, f := range soft.Flows {
				if i == 3 {
					val += "\n..."
					break
				}
				val += "\n" + f
			}

			ent := trx.AddEntity("netcap.Software", val)
			ent.AddProperty("timestamp", "Timestamp", "strict", soft.Timestamp)
			ent.AddProperty("vendor", "Vendor", "strict", soft.Vendor)
			ent.AddProperty("product", "Product", "strict", soft.Product)
			ent.AddProperty("version", "Version", "strict", soft.Version)
			ent.AddProperty("flows", "Flows", "strict", strings.Join(soft.Flows, " | "))
			ent.AddProperty("sourcename", "SourceName", "strict", soft.SourceName)
			ent.AddProperty("sourcedata", "SourceData", "strict", soft.SourceData)
			ent.AddProperty("notes", "Notes", "strict", soft.Notes)
		},
	)
}
