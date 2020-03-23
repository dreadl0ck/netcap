package main

import (
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"github.com/dreadl0ck/netcap/types"
	"log"
	"net/url"
)

func main() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, http *types.HTTP, minPackets, maxPackets uint64, profilesFile string, ipaddr string) {
			if http.SrcIP == ipaddr {
				host := lt.Value
				if http.Host == host {
					if http.URL != "" {
						bareURL := http.Host + StripQueryString(http.URL)
						log.Println(bareURL)

						ent := trx.AddEntity("maltego.URL", bareURL)
						ent.SetType("maltego.URL")
						ent.SetValue(bareURL)

						ent.AddProperty("url", "URL", "strict", bareURL)

						// di := "<h3>URL</h3><p>Timestamp: " + http.Timestamp + "</p>"
						// ent.AddDisplayInformation(di, "Netcap Info")

						//ent.SetLinkLabel(strconv.FormatInt(dns..NumPackets, 10) + " pkts")
						ent.SetLinkColor("#000000")
						//ent.SetLinkThickness(maltego.GetThickness(ip.NumPackets))
					}
				}
			}
		},
	)
}

func StripQueryString(inputUrl string) string {
	u, err := url.Parse(inputUrl)
	if err != nil {
		panic(err)
	}
	u.RawQuery = ""
	return u.String()
}