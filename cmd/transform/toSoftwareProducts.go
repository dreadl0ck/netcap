package transform

import (
	"strings"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toSoftwareProducts() {
	maltego.SoftwareTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, soft *types.Software, min, max uint64, path string, mac string, ipaddr string) {
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

			ent := trx.AddEntityWithPath("netcap.Software", val, path)
			ent.AddProperty("timestamp", "Timestamp", "strict", utils.UnixTimeToUTC(soft.Timestamp))
			ent.AddProperty("vendor", "Vendor", "strict", soft.Vendor)
			ent.AddProperty("product", "Product", "strict", soft.Product)
			ent.AddProperty("version", "Version", "strict", soft.Version)
			ent.AddProperty("flows", "Flows", "strict", strings.Join(soft.Flows, " | "))
			ent.AddProperty("sourcename", "SourceName", "strict", soft.SourceName)
			ent.AddProperty("sourcedata", "SourceData", "strict", soft.SourceData)
			ent.AddProperty("notes", "Notes", "strict", soft.Notes)

			ent.AddDisplayInformation(strings.Join(soft.Flows, "<br>"), "Flows")
		},
	)
}
