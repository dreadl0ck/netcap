package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToMailAuthTokens() {
	maltego.POP3Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, pop3 *types.POP3, min, max uint64, profilesFile string, ipaddr string) {
			if pop3.ClientIP == ipaddr {
				if pop3.AuthToken != "" {
					ent := trx.AddEntity("maltego.Token", pop3.AuthToken)
					ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)
					ent.AddProperty("path", "Path", "strict", profilesFile)
				}
			}
		},
	)
}
