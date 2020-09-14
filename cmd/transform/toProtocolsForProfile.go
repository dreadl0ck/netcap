package transform

import (
	"github.com/dreadl0ck/netcap/utils"
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toApplicationsForProfile() {
	maltego.IPProfileTransform(maltego.CountIPPackets, func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ip string) {

		if profile.Addr == ip {
			for protoName, proto := range profile.Protocols {
				ent := trx.AddEntityWithPath("netcap.Application", protoName, path)

				di := "<h3>Application</h3><p>Timestamp first seen: " + utils.UnixTimeToUTC(profile.TimestampFirst) + "</p>"
				ent.AddDisplayInformation(di, "Netcap Info")

				ent.SetLinkLabel(strconv.FormatInt(int64(proto.Packets), 10) + " pkts")
			}
		}
	})
}
