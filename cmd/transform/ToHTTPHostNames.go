package transform

import (
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToHTTPHostNames() {

	var hostStats = make(map[string]int)

	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, profilesFile string, ipaddr string) {
			if http.Host != "" {
				ent := trx.AddEntity("netcap.Website", http.Host)

				hostStats[http.Host]++
				ent.SetLinkLabel(strconv.Itoa(hostStats[http.Host]))
				//ent.SetLinkThickness(maltego.GetThickness(ip.NumPackets))

				ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)
				ent.AddProperty("path", "Path", "strict", profilesFile)
			}
		},
		false,
	)
}
