package transform

import (
	"fmt"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toHosts() {
	var (
		profiles = maltego.LoadIPProfiles()
		hosts    = make(map[string]struct{})
		pathName string
	)

	maltego.POP3Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, pop3 *types.POP3, min, max uint64, path string, ipaddr string) {
			hosts[pop3.ServerIP] = struct{}{}
			hosts[pop3.ClientIP] = struct{}{}
			if pathName == "" {
				pathName = path
			}
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
