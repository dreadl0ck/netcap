package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"log"
)

func toProvidersForURL() {
	var (
		p = maltego.LoadIPProfiles()
		ips = make(map[string]struct{})
		url string
		host string
	)

	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {

			if url == "" {
				url = lt.Values["properties.url"]
				host = lt.Values["host"]
				if url == "" || host == "" {
					die("properties.url or host is not set", "")
				}
				log.Println("got URL", url, "and host", host, "ipaddr", ipaddr)
			}

			if http.Host == host {
				if http.URL == "" {
					return
				}

				if http.URL != url  {
					return
				}

				if http.SrcIP != ipaddr {
					return
				}

				// check if dstIP host has already been added
				if _, ok := ips[http.DstIP]; !ok {
					if profile, exists := p[http.DstIP]; exists {
						addIPProfile(trx, profile, path, min, max)
					}
					ips[http.DstIP] = struct{}{}
				}
			}
		},
		false,
	)
}
