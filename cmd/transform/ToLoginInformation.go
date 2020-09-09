package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toLoginInformation() {
	maltego.CredentialsTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, cred *types.Credentials, min, max uint64, path string, mac string, ipaddr string) {
			val := cred.User + "\n" + cred.Password + "\n" + cred.Service
			if len(cred.Notes) > 0 {
				val += "\n" + cred.Notes
			}

			ent := trx.AddEntityWithPath("netcap.Credentials", val, path)
			ent.AddProperty("timestamp", "Timestamp", "strict", utils.UnixTimeToUTC(cred.Timestamp))
			ent.AddProperty("service", "Service", "strict", cred.Service)
			ent.AddProperty("flow", "Flow", "strict", cred.Flow)
			ent.AddProperty("notes", "Notes", "strict", cred.Notes)
			ent.AddProperty("user", "User", "strict", cred.User)
			ent.AddProperty("password", "Password", "strict", cred.Password)
		},
	)
}
