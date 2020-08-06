package transform

import (
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toApplications() {
	maltego.IPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if profile.MacAddr == mac {
				for _, ip := range profile.Contacts {
					if ip.Addr == ipaddr {
						for protoName, proto := range ip.Protocols {
							ent := trx.AddEntity("maltego.Service", protoName)

							di := "<h3>Application</h3><p>Timestamp first seen: " + ip.TimestampFirst + "</p>"
							ent.AddDisplayInformation(di, "Netcap Info")

							ent.SetLinkLabel(strconv.FormatInt(int64(proto.Packets), 10) + " pkts")
						}

						break
					}
				}
				for _, ip := range profile.DeviceIPs {
					if ip.Addr == ipaddr {
						for protoName, proto := range ip.Protocols {
							ent := trx.AddEntity("maltego.Service", protoName)

							di := "<h3>Application</h3><p>Timestamp first seen: " + ip.TimestampFirst + "</p>"
							ent.AddDisplayInformation(di, "Netcap Info")

							ent.SetLinkLabel(strconv.FormatInt(int64(proto.Packets), 10) + " pkts")
						}

						break
					}
				}
			}
		},
	)
}
