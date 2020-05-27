package transform

import (
	"fmt"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"log"
)

func LookupDHCPFingerprint() {

	var results = map[string]int{}

	// init API key
	resolvers.InitDHCPFingerprintAPIKey()

	// TODO: read HTTP audit records and create a map of useragents to ips

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

			// search vendor class
			var vendor string
			for _, o := range dhcp.Options {
				if utils.IsAscii(o.Data) && len(o.Data) > 1 {
					if o.Type == 60 {
						vendor = string(o.Data)
						break
					}
				}
			}

			val := maltego.EscapeText(ident)
			ent := trx.AddEntity("netcap.DHCPResult", val)
			ent.SetType("netcap.DHCPResult")
			ent.SetValue(val)

			ent.AddProperty("timestamp", "Timestamp", "strict", maltego.EscapeText(dhcp.Timestamp))
			ent.AddProperty("clientIP", "ClientIP", "strict", maltego.EscapeText(dhcp.ClientIP))
			ent.AddProperty("serverIP", "ServerIP", "strict", maltego.EscapeText(dhcp.NextServerIP))

			// di := "<h3>DHCP Option</h3><p>Timestamp First: " + dhcp.Timestamp + "</p>"
			// ent.AddDisplayInformation(di, "Netcap Info")
			ent.SetLinkColor("#000000")
			//ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
		},
	)

	fmt.Println(results)
}
