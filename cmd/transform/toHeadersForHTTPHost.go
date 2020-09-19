package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"log"
)

func toHeadersForHTTPHost() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			host := lt.Value
			log.Println(http.Host)
			if http.Host == host {
				for name := range http.RequestHeader {
					addHeader(trx, name, utils.UnixTimeToUTC(http.Timestamp), ipaddr, path, http.Method, host)
				}
				for name := range http.ResponseHeader {
					addHeader(trx, name, utils.UnixTimeToUTC(http.Timestamp), ipaddr, path, http.Method, host)
				}
			}
		},
		false,
	)
}

func addHeader(trx *maltego.Transform, headerName string, timestamp string, ipaddr string, path string, method string, host string) {
	ent := trx.AddEntityWithPath("netcap.HTTPHeader", headerName, path)
	ent.AddProperty("ipaddr", "IPAddress", maltego.Strict, ipaddr)
	ent.AddProperty("host", "Host", maltego.Strict, host)
	ent.AddProperty("timestamp", "Timestamp", maltego.Strict, timestamp)
	ent.SetLinkLabel(method)
}
