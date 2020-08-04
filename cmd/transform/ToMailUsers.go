package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToMailUsers() {
	maltego.POP3Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, pop3 *types.POP3, min, max uint64, profilesFile string, ipaddr string) {
			if pop3.ClientIP == ipaddr {
				if pop3.User != "" {
					ent := trx.AddEntity("maltego.Person", pop3.User)
					ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)
					ent.AddProperty("path", "Path", "strict", profilesFile)
				}
			}
		},
	)
}
