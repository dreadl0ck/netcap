package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toCredentialsByService() {
	maltego.CredentialsTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, cred *types.Credentials, min, max uint64, path string, mac string, ipaddr string) {
			// TODO: only output the service names in first stage
			ent := trx.AddEntityWithPath("netcap.Credentials", cred.User+"\n"+cred.Password, path)

			ent.AddProperty("timestamp", "Timestamp", maltego.Strict, utils.UnixTimeToUTC(cred.Timestamp))
			ent.AddProperty("service", "Service", maltego.Strict, cred.Service)
			ent.AddProperty("flow", "Flow", maltego.Strict, cred.Flow)
			ent.AddProperty("notes", "Notes", maltego.Strict, cred.Notes)
			ent.AddProperty("user", "User", maltego.Strict, cred.User)
			ent.AddProperty("password", "Password", maltego.Strict, cred.Password)
		},
	)
}
