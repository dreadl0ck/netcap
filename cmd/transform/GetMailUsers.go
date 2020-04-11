package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func GetMailUsers() {
	maltego.POP3Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, pop3  *types.POP3, min, max uint64, profilesFile string, ipaddr string) {
			if pop3.ClientIP == ipaddr {
				if pop3.User != "" {
					escapedName := maltego.EscapeText(pop3.User)
					ent := trx.AddEntity("maltego.Person", escapedName)
					ent.SetType("maltego.Person")
					ent.SetValue(escapedName)

					// di := "<h3>Mail User</h3><p>Timestamp First: " + pop3.Timestamp + "</p>"
					// ent.AddDisplayInformation(di, "Netcap Info")
					ent.SetLinkColor("#000000")
					//ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))

					ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)
					ent.AddProperty("path", "Path", "strict", profilesFile)
				}
			}
		},
	)
}