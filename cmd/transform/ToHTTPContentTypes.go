package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToHTTPContentTypes() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, http *types.HTTP, min, max uint64, profilesFile string, ipaddr string) {
			if http.SrcIP == ipaddr || http.DstIP == ipaddr {

				if http.ContentTypeDetected != "" {
					// using ContentTypeDetected instead the one that was set on the HTTP request / response
					ent := trx.AddEntity("netcap.ContentType", http.ContentTypeDetected)
					ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)
					ent.AddProperty("path", "Path", "strict", profilesFile)
				}
				if http.ResContentTypeDetected != "" {
					// using ContentTypeDetected instead the one that was set on the HTTP request / response
					ent := trx.AddEntity("netcap.ContentType", http.ResContentTypeDetected)
					ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)
					ent.AddProperty("path", "Path", "strict", profilesFile)
				}
			}
		},
		false,
	)
}
