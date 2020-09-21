package transform

import (
	"log"
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toApplications() {
	maltego.IPProfileTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ipaddr string) {
			if profile.Addr == ipaddr {
				log.Println(profile.Applications)
				for app, info := range profile.Protocols {
					addApplication(app, info, trx, path, profile)
				}
			}
		},
	)
}

func addApplication(app string, info *types.Protocol, trx *maltego.Transform, path string, profile *types.IPProfile) {
	ent := trx.AddEntityWithPath("netcap.Application", app, path)

	di := "<h3>Application</h3><p>Timestamp first seen: " + utils.UnixTimeToUTC(profile.TimestampFirst) + "</p>"
	ent.AddDisplayInformation(di, "Netcap Info")

	ent.SetLinkLabel(strconv.FormatInt(int64(info.Packets), 10) + " pkts")
}
