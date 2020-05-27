package transform

import (
	"fmt"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"log"
)

func ToDHCPFingerprints() {

	var results = map[string]int{}

	maltego.DHCPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, dhcp *types.DHCPv4, min, max uint64, profilesFile string, ipaddr string) {

			// prevent duplicating results
			if _, ok := results[dhcp.Fingerprint]; ok {
				return
			}
			results[dhcp.Fingerprint]++

			log.Println("DHCP Fingerprint", dhcp.Fingerprint)

			val := maltego.EscapeText(dhcp.Fingerprint)
			ent := trx.AddEntity("netcap.DHCPFingerprint", val)

			ent.SetType("netcap.DHCPFingerprint")
			ent.SetValue(val)

			// di := "<h3>DHCP Option</h3><p>Timestamp First: " + dhcp.Timestamp + "</p>"
			// ent.AddDisplayInformation(di, "Netcap Info")
			ent.SetLinkColor("#000000")
			//ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))

			// TODO:
			//resolvers.LookupDHCPFingerprint(dhcp.Fingerprint)
		},
	)

	fmt.Println(results)
}
