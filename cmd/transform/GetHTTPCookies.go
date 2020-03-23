package main

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func GetHTTPCookies() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, http *types.HTTP, minPackets, maxPackets uint64, profilesFile string, ipaddr string) {
			if http.SrcIP == ipaddr {
				for _, c := range http.ReqCookies {
					addCookie(trx, c, http.Timestamp, ipaddr, profilesFile)
				}
				for _, c := range http.ResCookies {
					addCookie(trx, c, http.Timestamp, ipaddr, profilesFile)
				}
			}
		},
	)
}
