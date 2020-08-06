package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toCredentialsByService() {
	maltego.CredentialsTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, cred *types.Credentials, min, max uint64, profilesFile string, mac string, ipaddr string) {
			// TODO: only output the service names in first stage
			ent := trx.AddEntity("netcap.Credentials", cred.User+"\n"+cred.Password)

			ent.AddProperty("timestamp", "Timestamp", "strict", cred.Timestamp)
			ent.AddProperty("service", "Service", "strict", cred.Service)
			ent.AddProperty("flow", "Flow", "strict", cred.Flow)
			ent.AddProperty("notes", "Notes", "strict", cred.Notes)
			ent.AddProperty("user", "User", "strict", cred.User)
			ent.AddProperty("password", "Password", "strict", cred.Password)
		},
	)
}
