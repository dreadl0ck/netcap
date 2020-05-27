package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToLoginInformation() {
	maltego.CredentialsTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, cred *types.Credentials, min, max uint64, profilesFile string, mac string, ipaddr string) {

			val := cred.User + "\n" + cred.Password + "\n" + cred.Service
			if len(cred.Notes) > 0 {
				val += "\n" + cred.Notes
			}
			val = maltego.EscapeText(val)
			ent := trx.AddEntity("netcap.Credentials", val)
			ent.SetType("netcap.Credentials")
			ent.SetValue(val)

			ent.AddProperty("timestamp", "Timestamp", "strict", maltego.EscapeText(cred.Timestamp))
			ent.AddProperty("service", "Service", "strict", maltego.EscapeText(cred.Service))
			ent.AddProperty("flow", "Flow", "strict", maltego.EscapeText(cred.Flow))
			ent.AddProperty("notes", "Notes", "strict", maltego.EscapeText(cred.Notes))
			ent.AddProperty("user", "User", "strict", maltego.EscapeText(cred.User))
			ent.AddProperty("password", "Password", "strict", maltego.EscapeText(cred.Password))

			ent.SetLinkColor("#000000")
			//ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
		},
	)
}
