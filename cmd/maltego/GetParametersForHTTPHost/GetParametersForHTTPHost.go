package main

import (
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"github.com/dreadl0ck/netcap/types"
	"log"
	"net/url"
)

func main() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, http *types.HTTP, minPackets, maxPackets uint64, profilesFile string, ipaddr string) {
			if http.SrcIP == ipaddr {
				host := lt.Value
				if http.Host == host {

					url, err := url.Parse(http.URL)
					if err != nil {
						log.Println(err)
						return
					}

					// map[string][]string
					for key, _ := range url.Query() {
						ent := trx.AddEntity("netcap.HTTPParameter", key)
						ent.SetType("netcap.HTTPParameter")
						ent.SetValue(key)

						di := "<h3>HTTP Parameter</h3><p>Timestamp: " + http.Timestamp + "</p>"
						ent.AddDisplayInformation(di, "Netcap Info")

						ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)
						ent.AddProperty("path", "Path", "strict", profilesFile)

						//ent.SetLinkLabel(strconv.FormatInt(dns..NumPackets, 10) + " pkts")
						ent.SetLinkColor("#000000")
						//ent.SetLinkThickness(maltego.GetThickness(ip.NumPackets))
					}
				}
			}
		},
	)
}
