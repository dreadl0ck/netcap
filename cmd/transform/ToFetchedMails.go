package transform

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"log"
	"strings"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToFetchedMails() {
	maltego.POP3Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, pop3 *types.POP3, min, max uint64, profilesFile string, ipaddr string) {
			for _, m := range pop3.Mails {

				log.Println(m.Subject)

				var buf bytes.Buffer
				err := xml.EscapeText(&buf, []byte(m.Subject+"\n"+m.From))
				if err != nil {
					fmt.Println(err)
				}

				ent := trx.AddEntity("netcap.Email", buf.String())

				var attachments string
				for _, p := range m.Body {
					cType := p.Header["Content-Type"]
					if cType != "" && strings.Contains(p.Header["Content-Disposition"], "attachment") {
						attachments += "<br>Attachment Content Type: " + cType + "<br>"
						attachments += "Filename: " + p.Filename + "<br><br>"
						if p.Content != "" && p.Content != "\n" {
							attachments += p.Content + "<br>"
						}
					}
				}

				var body string
				for _, p := range m.Body {
					cType := p.Header["Content-Type"]
					if strings.Contains(cType, "text/plain") || cType == "" {
						body += p.Content + "\n"
					}
				}

				// escape XML
				buf.Reset()
				err = xml.EscapeText(&buf, []byte(body))
				if err != nil {
					fmt.Println(err)
				}

				di := "<h3>EMail: " + m.Subject + "</h3><p>Timestamp First: " + pop3.Timestamp + "</p><p>From: " + m.From + "</p><p>To: " + m.To + "</p><p>Text: " + buf.String() + "</p><p>Additional parts: " + attachments + "</p>"
				ent.AddDisplayInformation(di, "Netcap Info")
			}
		},
	)
}
