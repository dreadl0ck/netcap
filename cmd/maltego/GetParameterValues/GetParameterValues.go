package main

import (
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"github.com/dreadl0ck/netcap/types"
	"log"
	"net/url"
	"strings"
)

func main() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, http *types.HTTP, minPackets, maxPackets uint64, profilesFile string, ipaddr string) {
			if http.SrcIP == ipaddr {

				url, err := url.Parse(http.URL)
				if err != nil {
					log.Println(err)
					return
				}

				param := lt.Values["properties.httpparameter"]

				// map[string][]string
				for key, val := range url.Query() {
					if key == param {
						value := strings.Join(val, ";")
						ent := trx.AddEntity("netcap.HTTPParameterValue", value)
						ent.SetType("netcap.HTTPParameterValue")
						ent.SetValue(value)

						// di := "<h3>HTTP Parameter Value</h3><p>Timestamp: " + http.Timestamp + "</p>"
						// ent.AddDisplayInformation(di, "Netcap Info")

						//ent.SetLinkLabel(strconv.FormatInt(dns..NumPackets, 10) + " pkts")
						ent.SetLinkColor("#000000")
						//ent.SetLinkThickness(maltego.GetThickness(ip.NumPackets))
					}
				}

			}
		},
	)
}
