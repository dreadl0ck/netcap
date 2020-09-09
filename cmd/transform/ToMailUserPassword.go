package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toMailUserPassword() {
	maltego.POP3Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, pop3 *types.POP3, min, max uint64, path string, ipaddr string) {
			if pop3.ClientIP == ipaddr {
				user := lt.Value
				if pop3.User == user && pop3.Pass != "" {
					ent := trx.AddEntityWithPath("maltego.Password", pop3.Pass, path)
					ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)

				}
			}
		},
	)
}
