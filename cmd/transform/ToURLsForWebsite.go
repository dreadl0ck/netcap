package transform

import (
	"log"
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToURLsForWebsite() {
	urlStats := make(map[string]int)

	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, profilesFile string, ipaddr string) {
			host := lt.Value
			if http.Host == host {
				if http.URL != "" {
					bareURL := http.Host + StripQueryString(http.URL)
					log.Println(bareURL)

					ent := trx.AddEntity("netcap.URL", bareURL)

					// since netcap.URL is inheriting from maltego.URL, in order to set the URL field correctly, we need to prefix the id with properties.
					ent.AddProperty("properties.url", "URL", "strict", bareURL)

					urlStats[bareURL]++
					ent.SetLinkLabel(strconv.Itoa(urlStats[bareURL]) + "\n" + http.Method)
				}
			}
		},
		false,
	)
}
