package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"log"
	"strconv"
)

func ToURLsForWebsite() {

	var urlStats = make(map[string]int)

	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, http *types.HTTP, min, max uint64, profilesFile string, ipaddr string) {
			host := lt.Value
			if http.Host == host {
				if http.URL != "" {
					bareURL := maltego.EscapeText(http.Host + StripQueryString(http.URL))
					log.Println(bareURL)

					ent := trx.AddEntity("netcap.URL", bareURL)
					ent.SetType("netcap.URL")
					ent.SetValue(bareURL)

					// since netcap.URL is inheriting from maltego.URL, in order to set the URL field correctly, we need to prefix the id with properties.
					ent.AddProperty("properties.url", "URL", "strict", bareURL)

					// di := "<h3>URL</h3><p>Timestamp: " + http.Timestamp + "</p>"
					// ent.AddDisplayInformation(di, "Netcap Info")

					urlStats[bareURL]++
					ent.SetLinkLabel(strconv.Itoa(urlStats[bareURL]))
					ent.SetLinkColor("#000000")
					//ent.SetLinkThickness(maltego.GetThickness(ip.NumPackets))
				}
			}
		},
		false,
	)
}
