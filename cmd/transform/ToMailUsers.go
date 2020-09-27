package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toMailUsers() {
	maltego.POP3Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, pop3 *types.POP3, min, max uint64, path string, ipaddr string) {
			if pop3.ClientIP == ipaddr {
				if pop3.User != "" {
					ent := trx.AddEntityWithPath("maltego.Person", pop3.User, path)
					ent.AddProperty("ipaddr", "IPAddress", maltego.Strict, ipaddr)

				}
			}
		},
		false,
	)
}
