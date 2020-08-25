package transform

import (
	"fmt"
	"log"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toDHCPClients() {
	results := map[string]int{}

	maltego.DHCPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, dhcp *types.DHCPv4, min, max uint64, profilesFile string, ipaddr string) {
			// DHCP operations fall into four phases: server discovery, IP lease offer, IP lease request, and IP lease acknowledgement.
			// to identify the client we are only looking for server discovery messages for now
			if dhcp.Operation != 1 {
				return
			}
			log.Println("HW:", dhcp.ClientHWAddr+" FP: "+dhcp.Fingerprint)

			ident := dhcp.ClientHWAddr + "\n" + dhcp.Fingerprint

			// prevent duplicating results
			if _, ok := results[ident]; ok {
				return
			}
			results[ident]++

			// log.Println("ident", ident, dhcp.Fingerprint)

			ent := trx.AddEntity("netcap.DHCPClient", ident)

			ent.AddProperty("timestamp", "Timestamp", "strict", utils.UnixTimeToUTC(dhcp.Timestamp))
			ent.AddProperty("clientIP", "ClientIP", "strict", dhcp.ClientIP)
			ent.AddProperty("serverIP", "ServerIP", "strict", dhcp.NextServerIP)
			ent.AddProperty("fp", "Fingerprint", "strict", dhcp.Fingerprint)
			ent.AddProperty("clientMac", "ClientHWAddr", "strict", dhcp.ClientHWAddr)
			ent.AddProperty("path", "Path", "strict", lt.Values["path"])

			for _, o := range dhcp.Options {
				if utils.IsASCII([]byte(o.Data)) && len(o.Data) > 1 {
					switch o.Type {
					case 60:
						ent.AddProperty("vendor", "Vendor", "strict", string(o.Data))
					case 12:
						ent.AddProperty("host", "Hostname", "strict", string(o.Data))
					case 15:
						ent.AddProperty("domain", "Domain", "strict", string(o.Data))
					}
				}
			}
		},
		false,
	)

	fmt.Println(results)
}
