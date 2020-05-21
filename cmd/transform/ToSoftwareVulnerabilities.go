package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToSoftwareVulnerabilities() {
	maltego.VulnerabilityTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, vuln *types.Vulnerability, min, max uint64, profilesFile string, mac string, ipaddr string) {
			ent := trx.AddEntity("netcap.Vulnerability", vuln.Description)
			ent.SetType("netcap.Vulnerability")
			ent.SetValue(vuln.Description)

			ent.AddProperty("timestamp", "Timestamp", "strict", vuln.Timestamp)
			ent.AddProperty("id", "ID", "strict", vuln.ID)
			ent.AddProperty("file", "File", "strict", vuln.File)
			ent.AddProperty("notes", "Notes", "strict", vuln.Notes)
			ent.AddProperty("software", "Software", "strict", vuln.Software.Product + " " + vuln.Software.Version)

			ent.SetLinkColor("#000000")
			//ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
		},
	)
}
