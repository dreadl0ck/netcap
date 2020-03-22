package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"github.com/dreadl0ck/netcap/types"
	"log"
	"strings"
)

func main() {
	maltego.POP3Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, pop3  *types.POP3, minPackets, maxPackets uint64, profilesFile string, ipaddr string) {
			if pop3.Client == ipaddr {
				for _, m := range pop3.Mails {

					log.Println(m.Subject)

					var buf bytes.Buffer
					err := xml.EscapeText(&buf, []byte(m.Subject + "\n" + m.From))
					if err != nil {
						fmt.Println(err)
					}

					ent := trx.AddEntity("maltego.Email", buf.String())
					ent.SetType("maltego.Email")
					ent.SetValue(buf.String())

					di := "<h3>EMail</h3><p>Timestamp First: " + pop3.Timestamp + "</p>"
					ent.AddDisplayInformation(di, "Netcap Info")
					ent.SetLinkColor("#000000")
					//ent.SetLinkThickness(maltego.GetThickness(uint64(count), minPackets, maxPackets))

					var body string
					for _, p := range m.Body {
						if strings.HasPrefix(p.Header["Content-Type"], "text/plain") {
							body += p.Content + "\n"
						}
					}

					// escape XML
					buf.Reset()
					err = xml.EscapeText(&buf, []byte(body))
					if err != nil {
						fmt.Println(err)
					}
					ent.SetNote(buf.String())
				}
			}
		},
	)
}