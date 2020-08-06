package transform

import (
	"strings"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toSoftwareVulnerabilities() {
	maltego.VulnerabilityTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, vuln *types.Vulnerability, min, max uint64, profilesFile string, mac string, ipaddr string) {
			val := vuln.ID
			product := vuln.Software.Product + " / " + vuln.Software.Version
			if len(product) > 0 {
				// for splitting descriptions from exploitdb
				//parts := strings.Split(vuln.Description, "-")
				//if len(parts) > 1 {
				//	val = parts[0] + "\n" + strings.Join(parts[1:], "-")
				//}
				val += "\n" + product
			}
			if len(vuln.Description) > 0 {
				val += "\n" + vuln.Description
			}
			for i, f := range vuln.Software.Flows {
				if i == 3 {
					val += "\n..."

					break
				}
				val += "\n" + f
			}

			ent := trx.AddEntity("netcap.Vulnerability", val)
			ent.AddProperty("timestamp", "Timestamp", "strict", vuln.Timestamp)
			ent.AddProperty("id", "ID", "strict", vuln.ID)
			ent.AddProperty("notes", "Notes", "strict", vuln.Notes)
			ent.AddProperty("flows", "flows", "strict", strings.Join(vuln.Software.Flows, ","))
			ent.AddProperty("software", "Software", "strict", vuln.Software.Product+" "+vuln.Software.Version)
		},
	)
}
