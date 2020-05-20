package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToSSHClients() {
	maltego.SSHTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, ssh *types.SSH, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if ssh.IsClient {
				ent := trx.AddEntity("netcap.SSHClient", ssh.HASSH)
				ent.SetType("netcap.SSHClient")
				ent.SetValue(ssh.HASSH)

				ent.AddProperty("timestamp", "Timestamp", "strict", ssh.Timestamp)
				ent.AddProperty("ident", "Ident", "strict", ssh.Ident)
				ent.AddProperty("flow", "Flow", "strict", ssh.Flow)
				ent.AddProperty("algorithms", "Algorithms", "strict", ssh.Algorithms)

				ent.SetLinkColor("#000000")
				//ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
			}
		},
	)
}
