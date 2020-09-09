package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toMailFrom() {
	mails := maltego.LoadMails()

	maltego.POP3Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, pop3 *types.POP3, min, max uint64, path string, ipaddr string) {
			if pop3.ClientIP == ipaddr {
				for _, id := range pop3.MailIDs {
					if m, ok := mails[id]; ok {
						if m.From != "" {
							ent := trx.AddEntityWithPath("netcap.Email", m.From, path)
							ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)

						}
					}
				}
			}
		},
	)
}
