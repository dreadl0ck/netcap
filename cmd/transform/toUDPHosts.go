package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toUDPHosts() {

	var (
		profiles = maltego.LoadIPProfiles()
		hosts = make(map[string]struct{})
		pathName string
	)

	maltego.UDPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, udp *types.UDP, min, max uint64, path string, ipaddr string) {
			if path == "" {
				pathName = path
			}
			hosts[udp.SrcIP] = struct{}{}
			hosts[udp.DstIP] = struct{}{}
		},
		true,
	)

	trx := maltego.Transform{}
	for ip := range hosts {
		if p, ok := profiles[ip]; ok {
			addIPProfile(&trx, p, pathName, 0, 0)
		}
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
