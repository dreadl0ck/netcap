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
				for _, c := range http.ReqCookies {
					addCookie(trx, c, http.Timestamp)
				}
				for _, c := range http.ResCookies {
					addCookie(trx, c, http.Timestamp)
				}
			}
		},
	)
}

func addCookie(trx *maltego.MaltegoTransform, c *types.HTTPCookie, timestamp string) {
	ent := trx.AddEntity("netcap.HTTPCookie", c.Name)
	ent.SetType("netcap.HTTPCookie")
	ent.SetValue(c.Name)

	di := "<h3>HTTP Cookie</h3><p>Timestamp: " + timestamp + "</p>"
	ent.AddDisplayInformation(di, "Netcap Info")

	//ent.SetLinkLabel(strconv.FormatInt(dns..NumPackets, 10) + " pkts")
	ent.SetLinkColor("#000000")
	//ent.SetLinkThickness(maltego.GetThickness(ip.NumPackets))
}