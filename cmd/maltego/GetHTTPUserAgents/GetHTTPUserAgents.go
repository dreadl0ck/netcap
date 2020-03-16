package main

import (
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func main() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, http *types.HTTP, minPackets, maxPackets uint64, profilesFile string, ipaddr string) {
			if http.SrcIP == ipaddr {
				if http.UserAgent != "" {

					ent := trx.AddEntity("netcap.UserAgent", http.UserAgent)
					ent.SetType("netcap.UserAgent")
					ent.SetValue(http.UserAgent)

					di := "<h3>User Agent</h3><p>Timestamp: " + http.Timestamp + "</p>"
					ent.AddDisplayInformation(di, "Netcap Info")

					//ent.SetLinkLabel(strconv.FormatInt(dns..NumPackets, 10) + " pkts")
					ent.SetLinkColor("#000000")
					//ent.SetLinkThickness(maltego.GetThickness(ip.NumPackets))
				}
			}
		},
	)
}
