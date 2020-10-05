package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toProviderIPProfilesForHost() {
	var (
		p    = maltego.LoadIPProfiles()
		ips  = make(map[string]struct{})
		host string
	)

	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if host == "" {
				host = lt.Value
			}

			if http.Host == host {
				if http.URL == "" {
					return
				}

				if http.DstIP != ipaddr {
					return
				}

				// check if srcIP host has already been added
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
