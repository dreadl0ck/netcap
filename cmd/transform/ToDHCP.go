package transform

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"log"
	"unicode/utf8"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toDHCP() {
	results := map[string]int{}

	maltego.DHCPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, dhcp *types.DHCPv4, min, max uint64, profilesFile string, ipaddr string) {
			if dhcp.ClientIP == ipaddr {
				for _, o := range dhcp.Options {
					if utf8.Valid([]byte(o.Data)) && len(o.Data) != 1 {

						// prevent duplicating results
						if _, ok := results[o.Data]; ok {
							return
						}
						results[o.Data]++

						log.Println(o.Data, len(o.Data))

						var buf bytes.Buffer
						err := xml.EscapeText(&buf, []byte(o.Data))
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

						trx.AddEntity("netcap.Device", typ+": "+buf.String())
					}
				}
			}
		},
		false,
	)

	log.Println(results)
}
