package main

import (
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func main() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, http *types.HTTP, minPackets, maxPackets uint64, profilesFile string, ipaddr string) {
			if http.SrcIP == ipaddr {
				if http.StatusCode != 0 {

					val := strconv.FormatInt(int64(http.StatusCode), 10)
					ent := trx.AddEntity("netcap.HTTPStatusCode", val)
					ent.SetType("netcap.HTTPStatusCode")
					ent.SetValue(val)

					// di := "<h3>HTTP Status Code</h3><p>Timestamp: " + http.Timestamp + "</p>"
					// ent.AddDisplayInformation(di, "Netcap Info")

					//ent.SetLinkLabel(strconv.FormatInt(dns..NumPackets, 10) + " pkts")
					ent.SetLinkColor("#000000")
					//ent.SetLinkThickness(maltego.GetThickness(ip.NumPackets))
				}
			}
		},
	)
}
