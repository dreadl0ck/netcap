package main

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func GetParameterValues() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, http *types.HTTP, min, max uint64, profilesFile string, ipaddr string) {
			if http.SrcIP == ipaddr {

				param := lt.Values["properties.httpparameter"]
				for key, val := range http.Parameters {
					if key == param {
						escapedName := maltego.EscapeText(val)
						ent := trx.AddEntity("netcap.HTTPParameterValue", escapedName)
						ent.SetType("netcap.HTTPParameterValue")
						ent.SetValue(escapedName)

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
