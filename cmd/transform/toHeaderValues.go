package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toHeaderValues() {
	var (
		headerName string
		host       string
	)
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if host == "" {
				headerName = lt.Values["properties.httpheader"]
				host = lt.Values["host"]
				if host == "" {
					die("host not set", "")
				}
			}
			if http.Host == host || http.SrcIP == ipaddr {
				if val, ok := http.RequestHeader[headerName]; ok {
					addHeaderValue(trx, val, path, host, headerName)
				}
				if val, ok := http.ResponseHeader[headerName]; ok {
					addHeaderValue(trx, val, path, host, headerName)
				}
			}
		},
		false,
	)
}

func addHeaderValue(trx *maltego.Transform, headerValue string, path string, host string, headerName string) {
	ent := trx.AddEntityWithPath("netcap.HTTPHeaderValue", headerValue, path)
	ent.AddProperty("host", "Host", maltego.Strict, host)
	ent.AddProperty("headername", "HeaderName", maltego.Strict, headerName)
}
