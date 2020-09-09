package transform

import (
	"log"
	"net/url"
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toURLsForHost() {
	urlStats := make(map[string]int)

	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if http.SrcIP != ipaddr {
				return
			}
			if http.URL == "" {
				return
			}
			bareURL := http.Host + stripQueryString(http.URL)
			log.Println(bareURL)

			ent := trx.AddEntityWithPath("netcap.URL", bareURL, path)

			// since netcap.URL is inheriting from maltego.URL, in order to set the URL field correctly, we need to prefix the id with properties.
			ent.AddProperty("properties.url", "URL", "strict", bareURL)

			urlStats[bareURL]++
			ent.SetLinkLabel(strconv.Itoa(urlStats[bareURL]) + "\n" + http.Method)
		},
		false,
	)
}

func stripQueryString(inputUrl string) string {
	u, err := url.Parse(inputUrl)
	if err != nil {
		panic(err)
	}
	u.RawQuery = ""
	return u.String()
}
