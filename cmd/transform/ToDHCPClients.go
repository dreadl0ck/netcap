package transform

import (
	"fmt"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"log"
)

func ToDHCPClients() {

	var results = map[string]int{}

	maltego.DHCPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, dhcp *types.DHCPv4, min, max uint64, profilesFile string, ipaddr string) {

			ident := dhcp.ClientIP + "\n" + dhcp.Fingerprint

			// prevent duplicating results
			if _, ok := results[ident]; ok {
				return
			}
			results[ident]++

			log.Println("ident", ident)

			val := maltego.EscapeText(ident)
			ent := trx.AddEntity("netcap.DHCPClient", val)
			ent.SetType("netcap.DHCPClient")
			ent.SetValue(val)

			ent.AddProperty("timestamp", "Timestamp", "strict", maltego.EscapeText(dhcp.Timestamp))
			ent.AddProperty("clientIP", "ClientIP", "strict", maltego.EscapeText(dhcp.ClientIP))
			ent.AddProperty("serverIP", "ServerIP", "strict", maltego.EscapeText(dhcp.NextServerIP))

			// di := "<h3>DHCP Option</h3><p>Timestamp First: " + dhcp.Timestamp + "</p>"
			// ent.AddDisplayInformation(di, "Netcap Info")
			ent.SetLinkColor("#000000")
			//ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))

			for _, o := range dhcp.Options {
				if utils.IsAscii(o.Data) && len(o.Data) > 1 {
					switch o.Type {
					case 60:
						ent.AddProperty("vendor", "Vendor", "strict", maltego.EscapeText(string(o.Data)))
					case 12:
						ent.AddProperty("host", "Hostname", "strict", maltego.EscapeText(string(o.Data)))
					case 15:
						ent.AddProperty("domain", "Domain", "strict", maltego.EscapeText(string(o.Data)))
					}
				}
			}
		},
	)

	fmt.Println(results)
}
