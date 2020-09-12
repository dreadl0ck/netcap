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
			ent.AddProperty("timestamp", "Timestamp", maltego.Strict, utils.UnixTimeToUTC(soft.Timestamp))
			ent.AddProperty("vendor", "Vendor", maltego.Strict, soft.Vendor)
			ent.AddProperty("product", "Product", maltego.Strict, soft.Product)
			ent.AddProperty("version", "Version", maltego.Strict, soft.Version)
			ent.AddProperty("flows", "Flows", maltego.Strict, strings.Join(soft.Flows, " | "))
			ent.AddProperty("sourcename", "SourceName", maltego.Strict, soft.SourceName)
			ent.AddProperty("sourcedata", "SourceData", maltego.Strict, soft.SourceData)
			ent.AddProperty("notes", "Notes", maltego.Strict, soft.Notes)

			ent.AddDisplayInformation(strings.Join(soft.Flows, "<br>"), "Flows")
		},
	)
}
