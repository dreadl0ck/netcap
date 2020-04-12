package transform

import (
	"bytes"
	"encoding/xml"
	"fmt"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"log"
	"unicode/utf8"
)

func GetDHCP() {

	var results = map[string]int{}

	maltego.DHCPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, dhcp *types.DHCPv4, min, max uint64, profilesFile string, ipaddr string) {
			if dhcp.ClientIP == ipaddr {
				for _, o := range dhcp.Options {
					if utf8.Valid(o.Data) && len(o.Data) != 1 {

						// prevent duplicating results
						if _, ok := results[string(o.Data)]; ok {
							return
						}
						results[string(o.Data)]++

						log.Println(string(o.Data), len(o.Data))

						var buf bytes.Buffer
						err := xml.EscapeText(&buf, o.Data)
						if err != nil {
							fmt.Println(err)
						}

						var typ string
						switch o.Type {
						case 60:
							typ = "Vendor Class Identifier"
						case 12:
							typ = "Hostname"
						case 15:
							typ = "Domain Name"
						}

						ent := trx.AddEntity("maltego.Device", typ+": "+buf.String())
						ent.SetType("netcap.Device")
						ent.SetValue(typ + ": " + buf.String())

						// di := "<h3>DHCP Option</h3><p>Timestamp First: " + dhcp.Timestamp + "</p>"
						// ent.AddDisplayInformation(di, "Netcap Info")
						ent.SetLinkColor("#000000")
						//ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
					}
				}
			}
		},
	)

	fmt.Println(results)
}
