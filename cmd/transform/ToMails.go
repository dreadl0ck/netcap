/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package transform

import (
	"bytes"
	"encoding/xml"
	"fmt"
	netmaltego "github.com/dreadl0ck/netcap/maltego"
	"strings"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toMails() {
	mails := netmaltego.LoadMails()

	netmaltego.POP3Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, pop3 *types.POP3, min, max uint64, path string, ipaddr string) {
			if pop3.ClientIP == ipaddr {
				for _, id := range pop3.MailIDs {
					if m, ok := mails[id]; ok {

						var buf bytes.Buffer
						err := xml.EscapeText(&buf, []byte(m.Subject+"\n"+m.From))
						if err != nil {
							fmt.Println(err)
						}

						ent := addEntityWithPath(trx, "netcap.Email", buf.String(), path)

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

						di := "<h3>EMail: " + m.Subject + "</h3><p>Timestamp First: " + utils.UnixTimeToUTC(pop3.Timestamp) + "</p><p>From: " + m.From + "</p><p>To: " + m.To + "</p><p>Text: " + buf.String() + "</p><p>Additional parts: " + attachments + "</p>"
						ent.AddDisplayInformation(di, "Netcap Info")
					}
				}
			}
		},
		false,
	)
}
