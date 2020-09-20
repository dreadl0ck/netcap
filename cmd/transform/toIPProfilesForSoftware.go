package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toIPProfilesForSoftware() {
	var (
		product string
		version string
		vendor  string
		p       = maltego.LoadIPProfiles()
		ips     = make(map[string]struct{})
	)
	maltego.SoftwareTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, soft *types.Software, min, max uint64, path string, mac string, ipaddr string) {

			if product == "" {
				product = lt.Values["product"]
				version = lt.Values["version"]
				vendor = lt.Values["vendor"]
				if product == "" && vendor == "" && version == "" {
					die("product, vendor and version are not set in properties!", "")
				}
			}

			if soft.Vendor == vendor && soft.Product == product && soft.Version == version {
				for _, f := range soft.Flows {
					srcIP, _, dstIP, _ := utils.ParseFlowIdent(f)

					// check if srcIP host has already been added
					if _, ok := ips[srcIP]; !ok {
						if profile, exists := p[srcIP]; exists {
							addIPProfile(trx, profile, path, min, max)
						}
						ips[srcIP] = struct{}{}
					}

					// check if dstIP host has already been added
					if _, ok := ips[dstIP]; !ok {
						if profile, exists := p[dstIP]; exists {
							addIPProfile(trx, profile, path, min, max)
						}
						ips[dstIP] = struct{}{}
					}
				}

			}
		},
	)
}
