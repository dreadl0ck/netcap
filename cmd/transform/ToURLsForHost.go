package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"log"
	"net/url"
	"strconv"
)

func toURLsForHost() {
	urlStats := make(map[string]int)

	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if http.SrcIP == ipaddr || http.DstIP == ipaddr {
				if http.URL == "" {
					return
				}

				bareURL := stripQueryString(http.URL)
				log.Println(bareURL)

				ent := trx.AddEntityWithPath("netcap.URL", bareURL, path)

				// since netcap.URL is inheriting from maltego.URL, in order to set the URL field correctly, we need to prefix the id with properties.
				ent.AddProperty("properties.url", "URL", maltego.Strict, bareURL)
				ent.AddProperty("host", "Host", maltego.Strict, http.Host)
				ent.AddProperty(maltego.PropertyIpAddr, maltego.PropertyIpAddrLabel, maltego.Strict, ipaddr)

				urlStats[bareURL]++
				ent.SetLinkLabel(strconv.Itoa(urlStats[bareURL]) + "\n" + http.Method)
			}
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
